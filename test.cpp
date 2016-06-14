#include "j2534.h"
#include <vector>
#include <list>
#include <mutex>
#include <condition_variable>
#include <thread>

#define UNUSED(x) (void)(x)
#ifdef DEBUG
#define LOG_DEBUG(...) printf(__VA_ARGS__); printf("\n"); fflush(stdout)
#else //DEBUG
#define LOG_DEBUG(...)
#endif //DEBUG

class J2534ChannelTest;

typedef std::shared_ptr <J2534ChannelTest> J2534ChannelTestPtr;
typedef std::weak_ptr <J2534ChannelTest> J2534ChannelTestWeakPtr;

class Bus;

typedef std::shared_ptr <Bus> BusPtr;
typedef std::weak_ptr <Bus> BusWeakPtr;

class Bus: public std::enable_shared_from_this<Bus> {
    friend class J2534ChannelTest;
public:
    Bus();
    ~Bus();
    void addChannel(const J2534ChannelTestPtr &channel);
    void removeChannel(const J2534ChannelTestPtr &channel);

    void run();
private:
    std::list<J2534ChannelTestPtr> mChannels;
    
    bool mContinue;
    std::thread mThread;
    std::mutex mMutex;
    std::list<J2534ChannelTestPtr> mIncommingMessageChannels;
    std::condition_variable mInterrupted;
};

class J2534ChannelTest: public J2534Channel {
    friend class Bus;
public: 
    J2534ChannelTest();
    
    virtual size_t readMsgs(std::vector <PASSTHRU_MSG> &msgs, TimeType Timeout);

    virtual size_t writeMsgs(std::vector <PASSTHRU_MSG> &msgs, TimeType Timeout);

    virtual PeriodicMessage startPeriodicMsg(PASSTHRU_MSG *pMsg, TimeType TimeInterval);

    virtual void stopPeriodicMsg(PeriodicMessage periodicMessage);

    virtual MessageFilter startMsgFilter(unsigned long FilterType, PASSTHRU_MSG *pMaskMsg, PASSTHRU_MSG *pPatternMsg,
                                         PASSTHRU_MSG *pFlowControlMsg);

    virtual void stopMsgFilter(MessageFilter messageFilter);

    virtual void ioctl(unsigned long IoctlID, void *pInput, void *pOutput);

    virtual J2534DevicePtr getDevice() const;
    
private:
    BusWeakPtr mBus;
    
    std::list<PASSTHRU_MSG> mInBuffers;
    std::list<PASSTHRU_MSG> mOutBuffers;
    
    std::mutex mMutex;
    std::condition_variable mInterrupted;
};


Bus::Bus(): mContinue(true), mThread(run, this) {
}

Bus::~Bus() {
   mContinue = false;
   {
       std::unique_lock<std::mutex> lck(mMutex);
       mInterrupted.notify_all();
   }
   mThread.join();
}

void Bus::addChannel(const J2534ChannelTestPtr &channel) {
    std::unique_lock<std::mutex> lck (mMutex);
    channel->mBus = shared_from_this();
    mChannels.push_back(channel);
}
void Bus::removeChannel(const J2534ChannelTestPtr &channel) {
    std::unique_lock<std::mutex> lck (mMutex);
    channel->mBus.reset();
    mChannels.remove(channel);
}

static void printMsg(PASSTHRU_MSG &msg) {
#ifdef DEBUG
    for(unsigned int i = 0; i < msg.DataSize; ++i) {
        printf("%02x ", msg.Data[i]);
    }
    printf("\n");
#else //DEBUG
    UNUSED(msg);
#endif //DEBUG
}

void Bus::run() {
    std::unique_lock<std::mutex> lck (mMutex);
    while(mContinue) {
        mInterrupted.wait(lck);
        
        while(!mIncommingMessageChannels.empty()) {
            J2534ChannelTestPtr channel = mIncommingMessageChannels.front();
            
            std::unique_lock<std::mutex> lckC (channel->mMutex);
            
            while(!channel->mOutBuffers.empty()) {
                // Dispatch the incoming message to the other channel on the bus
                PASSTHRU_MSG &msg = channel->mOutBuffers.front();
                printMsg(msg);
                for(J2534ChannelTestPtr &c: mChannels) {
                    if(c != channel) {
                        std::unique_lock<std::mutex> lckC2 (c->mMutex);
                        c->mInBuffers.push_back(msg);
                        c->mInterrupted.notify_all();
                        LOG_DEBUG("%p -> %p", (void*)channel.get(), (void*)c.get());
                    }
                }
                channel->mOutBuffers.pop_front();
            }
            
            channel->mInterrupted.notify_all();
            mIncommingMessageChannels.pop_front();
        }
    }
}


J2534ChannelTest::J2534ChannelTest() {
}


size_t J2534ChannelTest::readMsgs(std::vector <PASSTHRU_MSG> &msgs, TimeType Timeout) {
    BusPtr bus = mBus.lock();
    if(!bus) {
        LOG_DEBUG("No connected to bus");
        return 0;
    }
    
    // Set Deadline
    std::chrono::time_point<std::chrono::steady_clock> deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(Timeout);
    
    size_t i = 0;
    std::unique_lock<std::mutex> lck (mMutex);
    for(PASSTHRU_MSG &msg: msgs) {
        while(mInBuffers.empty()) {
            if(mInterrupted.wait_until(lck, deadline) == std::cv_status::timeout) {
                return i;
            }
        }
        msg = mInBuffers.front();
        mInBuffers.pop_front();
        i++;
    }
    return i;
}

size_t J2534ChannelTest::writeMsgs(std::vector <PASSTHRU_MSG> &msgs, TimeType Timeout) {
    BusPtr bus = mBus.lock();
    if(!bus) {
        LOG_DEBUG("No connected to bus");
        return 0;
    }
    
    // Set Deadline
    std::chrono::time_point<std::chrono::steady_clock> deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(Timeout);    
    
    size_t i = 0;
    std::unique_lock<std::mutex> lck (mMutex);
    
    LOG_DEBUG("Send %d message(s)", msgs.size());
    for(PASSTHRU_MSG &msg: msgs) {
        mOutBuffers.push_back(msg);
        bus->mIncommingMessageChannels.push_back(std::static_pointer_cast<J2534ChannelTest>(shared_from_this()));
        bus->mInterrupted.notify_all();
        
        while(!mOutBuffers.empty()) {
            if(mInterrupted.wait_until(lck, deadline) == std::cv_status::timeout) {
                return i;
            }
        }
        
        i++;
    }
    return i;
}

J2534Channel::PeriodicMessage J2534ChannelTest::startPeriodicMsg(PASSTHRU_MSG *pMsg, TimeType TimeInterval) {
    UNUSED(pMsg);
    UNUSED(TimeInterval);
    return 0;
}

void J2534ChannelTest::stopPeriodicMsg(PeriodicMessage periodicMessage) {
    UNUSED(periodicMessage);
}

J2534Channel::MessageFilter J2534ChannelTest::startMsgFilter(unsigned long FilterType, PASSTHRU_MSG *pMaskMsg, PASSTHRU_MSG *pPatternMsg,
                                         PASSTHRU_MSG *pFlowControlMsg) {
    UNUSED(FilterType);
    UNUSED(pMaskMsg);
    UNUSED(pPatternMsg);
    UNUSED(pFlowControlMsg);
    return 0;
}

void J2534ChannelTest::stopMsgFilter(MessageFilter messageFilter) {
    UNUSED(messageFilter);
}

void J2534ChannelTest::ioctl(unsigned long IoctlID, void *pInput, void *pOutput) {
    UNUSED(pInput);
    UNUSED(pOutput);
    if(IoctlID == CLEAR_RX_BUFFER) {
        mInBuffers.clear();
    } else if(IoctlID == CLEAR_TX_BUFFER) {
        mOutBuffers.clear();
    }
}

J2534DevicePtr J2534ChannelTest::getDevice() const {
    return nullptr;
}

static void pid2Data(uint32_t pid, uint8_t *data) {
    data[0] = 0x1F & (pid >> 24);
    data[1] = 0xFF & (pid >> 16);
    data[2] = 0xFF & (pid >> 8);
    data[3] = 0xFF & (pid >> 0);
}


#define J2534_DATA_OFFSET 4
int main(int argc, char *argv[]) {
    UNUSED(argc);
    UNUSED(argv);
    BusPtr bus = std::make_shared<Bus>();
    J2534ChannelTestPtr channel1 = std::make_shared<J2534ChannelTest>();
    J2534ChannelTestPtr channel2 = std::make_shared<J2534ChannelTest>();
    bus->addChannel(channel1);
    bus->addChannel(channel2);
    
    J2534ChannelPtr c1 = createISO15765Channel(channel1);
    J2534ChannelPtr c2 = createISO15765Channel(channel2);
    
    std::vector<PASSTHRU_MSG> msgs2(1);
    msgs2.resize(1);
    std::vector<PASSTHRU_MSG> msgs1(1);
    msgs1.resize(1);
    
    uint32_t pid1 = 0x1234;
    uint32_t pid2 = 0x4321;
    size_t size = 1023;
    
    PASSTHRU_MSG &msg = msgs1[0];
    msg.DataSize = size + J2534_DATA_OFFSET;
    pid2Data(pid2, msg.Data);
    for(size_t i = 0; i < size; ++i) {
        msg.Data[i + J2534_DATA_OFFSET] = (uint8_t)(i%256);
    }
    
    // Set BS and STMIN
    SCONFIG CfgItem[2];
    SCONFIG_LIST Input;

    CfgItem[0].Parameter = ISO15765_BS;
    CfgItem[0].Value = 0x20; /* BlockSize is 32 frames */
    CfgItem[1].Parameter = ISO15765_STMIN;
    CfgItem[1].Value = 0x01; /* SeparationTime is 1 millisecond */
    Input.NumOfParams = 2; /* Configuration list has 2 items */
    Input.ConfigPtr = CfgItem;
    
    c1->ioctl(SET_CONFIG, &Input, NULL);
    c2->ioctl(SET_CONFIG, &Input, NULL);
    
    
    PASSTHRU_MSG maskMsg1, maskMsg2;
    PASSTHRU_MSG patternMsg1, patternMsg2;
    PASSTHRU_MSG flowControlMsg1, flowControlMsg2;
    
    pid2Data(pid1, patternMsg1.Data);
    pid2Data(0xFFFFFFFF, maskMsg1.Data);
    pid2Data(pid2, flowControlMsg1.Data);
    c1->startMsgFilter(FLOW_CONTROL_FILTER, &maskMsg1, &patternMsg1, &flowControlMsg1);
    
    pid2Data(pid2, patternMsg2.Data);
    pid2Data(0xFFFFFFFF, maskMsg2.Data);
    pid2Data(pid1, flowControlMsg2.Data);
    c2->startMsgFilter(FLOW_CONTROL_FILTER, &maskMsg2, &patternMsg2, &flowControlMsg2);
    
    
    // Start the test
    int written = 0;
    int read = 0;
    printf("Start\n");
    fflush(stdout);
    std::thread t([&]() {
        written = c1->writeMsgs(msgs1, 2000);
    });
    
    std::thread t2([&]() {
        read = c2->readMsgs(msgs2, 2000);
    });    
    
    t.join();
    t2.join();
    
    
    // Check the test
    if(msgs2[0].DataSize != (J2534_DATA_OFFSET + size)) {
        LOG_DEBUG("Wrong size");
        return -1;
    }
    
    //printMsg(msgs1[0]);
    //printMsg(msgs2[0]);

    if(memcmp(msgs1[0].Data, msgs2[0].Data, size + J2534_DATA_OFFSET) != 0) {
        LOG_DEBUG("Wrong content");
        return -2;
    }

    
    printf("Written %d\n", written);
    printf("Read %d\n", read);
    printf("Test OK!\n");
    
    return 0;
}