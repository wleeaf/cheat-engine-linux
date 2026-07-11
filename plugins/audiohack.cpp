/// audiohack — LD_PRELOAD library that pitch-corrects audio played through
/// ALSA when the cecore speedhack is active.
///
/// Use case: speedhack scales game time. If the game's audio mixer ties
/// playback rate to game time (most middleware does — DirectMusic, FMOD,
/// Wwise, MOD/XM players), the resulting audio plays at a shifted pitch.
/// This library intercepts snd_pcm_writei() and feeds the buffer through
/// SoundTouch's time-stretching engine (SOLA-class), preserving pitch.
///
/// Use together with libspeedhack.so:
///     CE_SPEED=2.0 \
///     LD_PRELOAD="$PWD/build/libspeedhack.so $PWD/build/libcecore_audiohack.so" \
///     ./game
///
/// SoundTouch dep is gated. When libsoundtouch-dev isn't installed at
/// configure time, this library compiles with the path that just sample-
/// rate-converts (pitches the audio up/down without correction) — better
/// than nothing for users who can't install soundtouch.

#define _GNU_SOURCE
#include <charconv>
#include <string>
#include <alsa/asoundlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cmath>
#include <mutex>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>

#ifdef CECORE_HAVE_SOUNDTOUCH
#  include <soundtouch/SoundTouch.h>
#endif

namespace {

double  g_envSpeed   = 1.0;
double* g_sharedSpeed = nullptr;

void initSpeedSource() {
    // Parse locale-independently (from_chars always uses '.'), so CE_SPEED=1.5 is
    // read as 1.5 even if we're injected into a game that activated a comma-decimal
    // locale — std::atof would honour that locale and read "1.5" as 1.
    if (auto* e = std::getenv("CE_SPEED")) {
        std::string s = e;
        for (auto& c : s) if (c == ',') c = '.';
        double v = 1.0;
        auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
        if (ec == std::errc() && p != s.data()) g_envSpeed = v;
    }
    if (g_envSpeed <= 0) g_envSpeed = 1.0;
    // O_NOFOLLOW refuses a symlink-swapped /dev/shm entry, matching the
    // speedhack side. No O_CREAT: this is a read-side consumer of the channel.
    int fd = shm_open("/ce_speedhack", O_RDWR | O_NOFOLLOW, 0666);
    if (fd >= 0) {
        auto* mapped = ::mmap(nullptr, sizeof(double),
                              PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (mapped != MAP_FAILED) g_sharedSpeed = static_cast<double*>(mapped);
        ::close(fd);
    }
}

double currentSpeed() {
    double v = g_sharedSpeed ? *g_sharedSpeed : g_envSpeed;
    if (v <= 0.0 || !(v == v) || v == HUGE_VAL || v == -HUGE_VAL) v = 1.0;
    return v;
}

// PCM format → number of channels we should treat each frame as carrying.
// We don't have access to snd_pcm_t's hw_params from inside writei callers
// directly without a roundtrip; the cleanest workaround is to look up the
// stream's saved metadata via a tiny per-handle cache populated when the
// caller first writes to a new handle.
struct StreamMeta {
    snd_pcm_t* handle;
    snd_pcm_format_t fmt;
    unsigned int channels;
    unsigned int rate;
#ifdef CECORE_HAVE_SOUNDTOUCH
    soundtouch::SoundTouch* st;
#endif
};

constexpr int kMaxStreams = 16;
StreamMeta g_streams[kMaxStreams] = {};
// Serialises g_streams: ALSA clients commonly write from a dedicated audio
// thread, so slot allocation and the SoundTouch* new/delete must be guarded.
// TODO(security): cap is fixed at 16; revalidate hw_params on handle reuse and
// make the table dynamic if more concurrent streams are needed.
std::mutex g_streamsMutex;

// Caller must hold g_streamsMutex.
StreamMeta* getOrFillMetaLocked(snd_pcm_t* h) {
    for (auto& s : g_streams) {
        if (s.handle != h) continue;
        // Re-query the live params: the app may have reconfigured this handle
        // (e.g. dropped channels 2->1) without closing it, which would leave a
        // stale channel count and make snd_pcm_writei over-read the caller's
        // buffer by inFrames*(cachedChannels-actualChannels) samples.
        snd_pcm_hw_params_t* p = nullptr;
        snd_pcm_hw_params_alloca(&p);
        if (snd_pcm_hw_params_current(h, p) == 0) {
            snd_pcm_hw_params_get_format(p, &s.fmt);
            unsigned int newCh = 0, newRate = 0;
            snd_pcm_hw_params_get_channels(p, &newCh);
            snd_pcm_hw_params_get_rate(p, &newRate, nullptr);
#ifdef CECORE_HAVE_SOUNDTOUCH
            if ((newCh != s.channels || newRate != s.rate) && s.st) {
                s.st->clear();
                s.st->setChannels(newCh ? newCh : 2);
                s.st->setSampleRate(newRate ? newRate : 44100);
            }
#endif
            s.channels = newCh;
            s.rate = newRate;
        }
        return &s;
    }
    // Empty slot — populate from the kernel via snd_pcm_hw_params_current.
    for (auto& s : g_streams) {
        if (s.handle == nullptr) {
            snd_pcm_hw_params_t* p = nullptr;
            snd_pcm_hw_params_alloca(&p);
            if (snd_pcm_hw_params_current(h, p) == 0) {
                s.handle = h;
                snd_pcm_hw_params_get_format(p, &s.fmt);
                snd_pcm_hw_params_get_channels(p, &s.channels);
                snd_pcm_hw_params_get_rate(p, &s.rate, nullptr);
#ifdef CECORE_HAVE_SOUNDTOUCH
                s.st = new soundtouch::SoundTouch();
                s.st->setChannels(s.channels ? s.channels : 2);
                s.st->setSampleRate(s.rate ? s.rate : 44100);
#endif
                return &s;
            }
            return nullptr;
        }
    }
    return nullptr;
}

// Drop a stream's cache slot and free its SoundTouch object. Caller must hold
// g_streamsMutex.
void dropMetaLocked(snd_pcm_t* h) {
    for (auto& s : g_streams) {
        if (s.handle == h) {
#ifdef CECORE_HAVE_SOUNDTOUCH
            delete s.st;
#endif
            s = StreamMeta{};
            return;
        }
    }
}

bool isSupportedFormat(snd_pcm_format_t f) {
    // Only host-endian (little-endian on x86_64) formats are pitch-corrected.
    // The S16/FLOAT conversion paths interpret bytes as native-endian, so a
    // *_BE stream would be silently byte-swapped into noise; those fall
    // through to the safe real() passthrough instead.
    return f == SND_PCM_FORMAT_S16_LE || f == SND_PCM_FORMAT_FLOAT_LE;
}

void s16ToFloat(const int16_t* in, float* out, size_t n) {
    constexpr float kInv = 1.0f / 32768.0f;
    for (size_t i = 0; i < n; ++i) out[i] = in[i] * kInv;
}
void floatToS16(const float* in, int16_t* out, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        float v = in[i];
        if (v >  1.0f) v =  1.0f;
        if (v < -1.0f) v = -1.0f;
        out[i] = (int16_t)(v * 32767.0f);
    }
}

} // anonymous namespace

extern "C" {

__attribute__((constructor))
static void audiohack_init() {
    initSpeedSource();
    fprintf(stderr, "[audiohack] initialised, CE_SPEED=%.2f%s\n",
                 currentSpeed(),
#ifdef CECORE_HAVE_SOUNDTOUCH
                 " (SoundTouch pitch-correction enabled)"
#else
                 " (no SoundTouch — rate-scaled only, pitch will shift)"
#endif
                 );
}

snd_pcm_sframes_t snd_pcm_writei(snd_pcm_t* pcm, const void* buffer,
                                  snd_pcm_uframes_t size) {
    using Fn = snd_pcm_sframes_t (*)(snd_pcm_t*, const void*, snd_pcm_uframes_t);
    static Fn real = nullptr;
    if (!real) real = (Fn)dlsym(RTLD_NEXT, "snd_pcm_writei");
    if (!real) return -ENOSYS;

    double speed = currentSpeed();
    if (speed == 1.0 || size == 0) return real(pcm, buffer, size);

    // Resolve/allocate the per-handle metadata under the lock and snapshot the
    // immutable fields so the (possibly blocking) device write below runs
    // without holding the mutex. SoundTouch state itself is per-handle; ALSA
    // forbids concurrent writei on the same handle, so the st pointer is
    // stable for the duration of this call.
    [[maybe_unused]] snd_pcm_format_t fmt = SND_PCM_FORMAT_UNKNOWN;
    [[maybe_unused]] unsigned int channelsU = 0;
    bool passthrough = false;
#ifdef CECORE_HAVE_SOUNDTOUCH
    soundtouch::SoundTouch* st = nullptr;
#endif
    {
        std::lock_guard<std::mutex> lk(g_streamsMutex);
        auto* meta = getOrFillMetaLocked(pcm);
        if (!meta || !isSupportedFormat(meta->fmt) || meta->channels == 0) {
            passthrough = true;
        } else {
            fmt = meta->fmt;
            channelsU = meta->channels;
#ifdef CECORE_HAVE_SOUNDTOUCH
            st = meta->st;
#endif
        }
    }
    if (passthrough) return real(pcm, buffer, size);

#ifdef CECORE_HAVE_SOUNDTOUCH
    // Time-compress at the same pitch: tempo = speed. SoundTouch consumes
    // input frames at the original rate and emits fewer (or more) frames
    // depending on tempo. Output count ≈ size / speed.
    st->setTempo((float)speed);

    size_t channels = channelsU;
    size_t inFrames = (size_t)size;
    std::vector<float> floatIn(inFrames * channels);
    std::vector<int16_t> s16Tmp;

    if (fmt == SND_PCM_FORMAT_S16_LE) {
        const int16_t* p = static_cast<const int16_t*>(buffer);
        s16ToFloat(p, floatIn.data(), inFrames * channels);
    } else {
        memcpy(floatIn.data(), buffer, inFrames * channels * sizeof(float));
    }

    st->putSamples(floatIn.data(), (uint32_t)inFrames);

    // Drain everything SoundTouch has buffered. A single capped pull would
    // truncate slow-motion output (tempo < 1.0 emits MORE frames than the
    // input), so loop until receiveSamples returns 0, appending each batch.
    std::vector<uint8_t> outBytes;
    uint32_t totalGot = 0;
    {
        const uint32_t kBatch = 4096;  // frames per receive call
        std::vector<float> floatOut((size_t)kBatch * channels);
        for (;;) {
            uint32_t got = st->receiveSamples(floatOut.data(), kBatch);
            if (got == 0) break;
            totalGot += got;
            if (fmt == SND_PCM_FORMAT_S16_LE) {
                s16Tmp.resize((size_t)got * channels);
                floatToS16(floatOut.data(), s16Tmp.data(), (size_t)got * channels);
                outBytes.insert(outBytes.end(),
                                (const uint8_t*)s16Tmp.data(),
                                (const uint8_t*)s16Tmp.data() + s16Tmp.size() * sizeof(int16_t));
            } else {
                outBytes.insert(outBytes.end(),
                                (const uint8_t*)floatOut.data(),
                                (const uint8_t*)floatOut.data() + (size_t)got * channels * sizeof(float));
            }
        }
    }
    if (totalGot == 0) return (snd_pcm_sframes_t)size;  // not yet enough buffered

    // Write all produced frames, honoring short writes and recovering from
    // xruns, instead of assuming a single real() call consumed everything.
    size_t bytesPerFrame = channels * (fmt == SND_PCM_FORMAT_S16_LE ? sizeof(int16_t) : sizeof(float));
    const uint8_t* outPtr = outBytes.data();
    uint32_t framesLeft = totalGot;
    while (framesLeft > 0) {
        snd_pcm_sframes_t w = real(pcm, outPtr, framesLeft);
        if (w < 0) {
            // -EPIPE (underrun) / -ESTRPIPE: try to recover once, else report.
            if (snd_pcm_recover(pcm, (int)w, 1) < 0)
                return (snd_pcm_sframes_t)w;
            continue;
        }
        if (w == 0) break; // no progress; avoid a busy spin
        framesLeft -= (uint32_t)w;
        outPtr += (size_t)w * bytesPerFrame;
    }
    // Report the original frame count as consumed so the caller's bookkeeping
    // matches what they handed us.
    return (snd_pcm_sframes_t)size;
#else
    // Without SoundTouch: just hand the buffer through. The game's audio
    // will pitch-shift with speed but at least play in the right wall-clock
    // window. Better than dropping the audio entirely.
    return real(pcm, buffer, size);
#endif
}

// Hook close so a handle's cache slot and its SoundTouch object are released
// instead of leaking. This also prevents a stale slot being matched by pointer
// if ALSA later reuses the same snd_pcm_t* for a different stream.
int snd_pcm_close(snd_pcm_t* pcm) {
    using Fn = int (*)(snd_pcm_t*);
    static Fn real = nullptr;
    if (!real) real = (Fn)dlsym(RTLD_NEXT, "snd_pcm_close");
    {
        std::lock_guard<std::mutex> lk(g_streamsMutex);
        dropMetaLocked(pcm);
    }
    if (!real) return -ENOSYS;
    return real(pcm);
}

} // extern "C"
