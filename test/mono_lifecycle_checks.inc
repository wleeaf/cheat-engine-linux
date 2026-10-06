// Transport ownership contracts: a numeric PID can still name a reachable
// socket after its original logical process handle has been invalidated.
static void monoLifecycleTests() {
    class LogicalTarget : public TargetBuffer {
    public:
        unsigned descriptions=0;
        bool firstLive=false;
        TargetDescription targetDescription() override {
            auto result=description;
            result.host=nativeTargetMachine();result.program=result.host;
            result.live=firstLive && ++descriptions==1;
            return result;
        }
    };
    namespace fs=std::filesystem;
    const auto directory=fs::path("/tmp")/ ("cecore_mono_"+std::to_string(getpid()));
    const auto path=(directory/"agent.sock").string();
    std::error_code error;
    const bool created=fs::create_directory(directory,error);
    if (error || !created) {
        check(false,"owned Mono lifecycle socket directory is unique");return;
    }
    for (unsigned scenario=0;scenario<3;++scenario) {
        int listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
        sockaddr_un address{};address.sun_family=AF_UNIX;
        std::memcpy(address.sun_path,path.c_str(),path.size()+1);
        bool listening=listener>=0 && bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0 &&
            listen(listener,1)==0;
        if (!listening) {
            if (listener>=0) close(listener);
            check(false,"owned Mono lifecycle socket listens");break;
        }
        bool connected=false,dispatched=false;
        std::thread peer([&] {
            pollfd poller{listener,POLLIN,0};
            if (poll(&poller,1,150)<=0) return;
            int client=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);
            if (client<0) return;
            connected=true;
            poller={client,POLLIN,0};
            if (poll(&poller,1,500)>0) {
                char bytes[64];dispatched=recv(client,bytes,sizeof(bytes),0)>0;
                if (dispatched) {
                    uint32_t response[]={htonl(CE_MONO_MAGIC),htonl(CE_MONO_OK),htonl(7)};
                    (void)send(client,response,sizeof(response),MSG_NOSIGNAL);
                    (void)send(client,"# done\n",7,MSG_NOSIGNAL);
                }
            }
            close(client);
        });
        LogicalTarget target;target.firstLive=scenario==2;
        SymbolResolver resolver;
        bool rejected=false;
        if (scenario==1)
            rejected=!findMonoFunction(target,resolver,"unused-agent","N","C","M",1,1000);
        else {
            auto result=dissectMono(target,resolver,"unused-agent",1000);
            rejected=result && !result->ready && !result->error.empty();
        }
        peer.join();close(listener);unlink(path.c_str());
        if (scenario==0)
            check(rejected && !connected && !dispatched,"an invalidated process handle never sends Mono metadata requests to its numeric PID");
        else if (scenario==1)
            check(rejected && !connected && !dispatched,"an invalidated process handle never sends Mono method requests to its numeric PID");
        else
            check(rejected && connected && !dispatched,"Mono revalidates handle ownership after connecting and before sending any request bytes");
    }
    fs::remove(directory,error);
}
