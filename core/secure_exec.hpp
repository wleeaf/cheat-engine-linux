#pragma once
// A binary given a file capability (the .deb grants cheatengine and cescan
// cap_sys_ptrace) runs as a secure-exec process: whoever starts it is not
// trusted with what the capability allows, which here is reading and writing
// any process on the machine. glibc then ignores LD_PRELOAD, LD_LIBRARY_PATH
// and similar, but Qt, GTK, GIO, Mesa, glvnd and the Vulkan loader still load
// plugins from places named in the environment, and Lua's unsafe opt-in would
// open package.loadlib. Any of these would run that user's code with the
// capability, past every check Cheat Engine makes on whose process it opens.

#include <sys/auxv.h>

#include <cstdlib>

namespace ce {

/// True when the kernel marked this process secure-exec (file capabilities,
/// setuid or setgid).
inline bool secureExecution() { return getauxval(AT_SECURE) != 0; }

/// In a secure-exec process, drop the environment variables that make a
/// library load code from a user-chosen path. Call first thing in main(),
/// before any toolkit initialises.
inline void scrubSecureEnvironment() {
    if (!secureExecution()) return;
    static const char* const codeLoading[] = {
        // Qt plugins and QML.
        "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QML2_IMPORT_PATH", "QML_IMPORT_PATH",
        "QT_QUICK_CONTROLS_STYLE_PATH",
        // GTK (the gtk3 platform theme), GIO and gdk-pixbuf modules.
        "GTK_MODULES", "GTK3_MODULES", "GTK_PATH", "GTK_EXE_PREFIX", "GTK_DATA_PREFIX",
        "GTK_IM_MODULE_FILE", "GIO_EXTRA_MODULES", "GIO_MODULE_DIR", "GDK_PIXBUF_MODULE_FILE",
        "GDK_PIXBUF_MODULEDIR",
        // OpenGL, EGL, VA-API, VDPAU and GBM drivers.
        "LIBGL_DRIVERS_PATH", "EGL_DRIVERS_PATH", "__EGL_VENDOR_LIBRARY_DIRS",
        "__EGL_VENDOR_LIBRARY_FILENAMES", "__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS",
        "__EGL_EXTERNAL_PLATFORM_CONFIG_FILENAMES", "__GLX_VENDOR_LIBRARY_NAME", "LIBVA_DRIVERS_PATH",
        "VDPAU_DRIVER_PATH", "GBM_BACKENDS_PATH",
        // Vulkan drivers and layers.
        "VK_ICD_FILENAMES", "VK_DRIVER_FILES", "VK_ADD_DRIVER_FILES", "VK_LAYER_PATH",
        "VK_ADD_LAYER_PATH", "VK_INSTANCE_LAYERS", "VK_LOADER_LAYERS_ENABLE",
        // ALSA configuration can name plugin libraries.
        "ALSA_CONFIG_PATH", "ALSA_PLUGIN_DIR",
        // Lua's unsafe opt-in (shellExecute, package.loadlib).
        "CECORE_LUA_ALLOW_UNSAFE",
    };
    for (const char* name : codeLoading) unsetenv(name);
}

} // namespace ce
