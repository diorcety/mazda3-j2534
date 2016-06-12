#include <string.h>
#include <map>
#include <chrono>
#include <thread>
#include <algorithm>
#include "j2534.h"

#define LOG_DEBUG(...) printf(__VA_ARGS__); printf("\n"); fflush(stdout)

class J2534DeviceImpl;

typedef std::shared_ptr <J2534DeviceImpl> J2534DeviceImplPtr;
typedef std::weak_ptr <J2534DeviceImpl> J2534DeviceImplWeakPtr;

class J2534ChannelImpl;

typedef std::shared_ptr <J2534ChannelImpl> J2534ChannelImplPtr;
typedef std::weak_ptr <J2534ChannelImpl> J2534ChannelImplWeakPtr;

class J2534LibraryImpl;

typedef std::shared_ptr <J2534LibraryImpl> J2534LibraryImplPtr;
typedef std::weak_ptr <J2534LibraryImpl> J2534LibraryImplWeakPtr;

class J2534LibraryImpl : public J2534Library {
    friend class J2534DeviceImpl;
    friend class J2534ChannelImpl;
public:
    J2534LibraryImpl(const char *library);

    virtual ~J2534LibraryImpl();

    virtual J2534DevicePtr open(void *pName);

    virtual void getLastError(char *pErrorDescription);

private:
    struct j2534_fcts {
        PTOPEN passThruOpen;
        PTCLOSE passThruClose;
        PTCONNECT passThruConnect;
        PTDISCONNECT passThruDisconnect;
        PTREADMSGS passThruReadMsgs;
        PTWRITEMSGS passThruWriteMsgs;
        PTSTARTPERIODICMSG passThruStartPeriodicMsg;
        PTSTOPPERIODICMSG passThruStopPeriodicMsg;
        PTSTARTMSGFILTER passThruStartMsgFilter;
        PTSTOPMSGFILTER passThruStopMsgFilter;
        PTSETPROGRAMMINGVOLTAGE passThruSetProgrammingVoltage;
        PTREADVERSION passThruReadVersion;
        PTGETLASTERROR passThruGetLastError;
        PTIOCTL passThruIoctl;
    } mFcts;
#ifdef _WIN32
    HMODULE mModule;
#else //_WIN32
    void *mModule;
#endif //_WIN32
};

class J2534DeviceImpl : public J2534Device {
    friend class J2534ChannelImpl;
public:
    J2534DeviceImpl(const J2534LibraryImplPtr &library, unsigned long device);

    virtual ~J2534DeviceImpl();

    virtual J2534ChannelPtr connect(unsigned long ProtocolID, unsigned long Flags, unsigned long BaudRate);

    virtual void setProgrammingVoltage(unsigned long PinNumber, unsigned long Voltage);

    virtual void readVersion(char *pFirmwareVersion, char *pDllVersion, char *pApiVersion);

    virtual void ioctl(unsigned long IoctlID, void *pInput, void *pOutput);

    virtual J2534LibraryPtr getLibrary() const;

private:
    J2534LibraryImplPtr mLibrary;
    unsigned long mDeviceID;
};

class J2534ChannelImpl : public J2534Channel {
public:
    typedef unsigned long TimeType;
    typedef unsigned long PeriodicMessage;
    typedef unsigned long MessageFilter;
    
    J2534ChannelImpl(const J2534DeviceImplPtr &device, unsigned long channel);

    virtual ~J2534ChannelImpl();

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
    J2534DeviceImplPtr mDevice;
    unsigned long mChannelID;
};


/*
 *
 * J2534LoadException
 *
 */

J2534LoadException::J2534LoadException(const char *error) {
    if (error != NULL) {
        mError.append(error);
    }
}

const char *J2534LoadException::what() const noexcept {
    return mError.c_str();
}

J2534FunctionException::J2534FunctionException(long code) : mCode(code) {
}

long J2534FunctionException::code() const {
    return mCode;
}

const char *J2534FunctionException::what() const noexcept {
    static char buffer[256];
    snprintf(buffer, 256, "Error code: %ld", mCode);
    return buffer;
}

/*
 *
 * Predeclare
 *
 */
 
class ISO15765Transfer;

class J2534ChannelISO15765: public J2534Channel {
    friend class ISO15765Transfer;
public:
    using typename J2534Channel::TimeType;
    using typename J2534Channel::MessageFilter;

    J2534ChannelISO15765(const J2534ChannelPtr &channel);

    virtual ~J2534ChannelISO15765();
    
    virtual MessageFilter startMsgFilter(unsigned long FilterType, PASSTHRU_MSG *pMaskMsg, PASSTHRU_MSG *pPatternMsg,
                                         PASSTHRU_MSG *pFlowControlMsg);

    virtual void stopMsgFilter(MessageFilter messageFilter);
    
    virtual size_t readMsgs(std::vector <PASSTHRU_MSG> &msg, TimeType Timeout);

    virtual size_t writeMsgs(std::vector <PASSTHRU_MSG> &msg, TimeType Timeout);
    
    virtual PeriodicMessage startPeriodicMsg(PASSTHRU_MSG *pMsg, TimeType TimeInterval);

    virtual void stopPeriodicMsg(PeriodicMessage periodicMessage);

    virtual J2534DevicePtr getDevice() const;
    
    virtual void ioctl(unsigned long IoctlID, void *pInput, void *pOutput);
    
    virtual int getBs() const;
    
    virtual int getStmin() const;
    
private:
    J2534ChannelPtr mChannel;
    
    int bs;
    int stmin;
    
    std::shared_ptr<ISO15765Transfer> getTransferByFlowControl(const PASSTHRU_MSG &msg);
    std::shared_ptr<ISO15765Transfer> getTransferByPattern(const PASSTHRU_MSG &msg);
    std::map<MessageFilter, std::shared_ptr<ISO15765Transfer>> mTransfers;
};
 
class ISO15765Transfer {
public:
    typedef unsigned long TimeType;
    ISO15765Transfer(J2534ChannelISO15765 &channel, const PASSTHRU_MSG &pMaskMsg, const PASSTHRU_MSG &pPatternMsg, const PASSTHRU_MSG &pFlowControlMsg);
    ~ISO15765Transfer();
    
    void clear();
    
    bool writeMsg(const PASSTHRU_MSG &msg, TimeType Timeout);
    bool readMsg(const PASSTHRU_MSG &in_msg, PASSTHRU_MSG &out_msg, TimeType Timeout);
    
    uint32_t getMaskPid();
    uint32_t getPatternPid();
    uint32_t getFlowControlPid();

private:
    enum TransferState {
        START_STATE = 0,
        FLOW_CONTROL_STATE,
        BLOCK_STATE
    };

    enum PCIFrameName {
        SingleFrame = 0,
        FirstFrame,
        ConsecutiveFrame,
        FlowControl,
        UnknownFrame
    };
    
    static PCIFrameName getFrameName(uint8_t pci);
    static uint8_t getPci(PCIFrameName frameName);
    static size_t getRemainingSize(const PASSTHRU_MSG &msg, off_t offset);
    static void prepareSentMessageHeaders(PASSTHRU_MSG &out_msg, const PASSTHRU_MSG &in_msg);
    static void prepareReceivedMessageHeaders(PASSTHRU_MSG &out_msg, const PASSTHRU_MSG &in_msg);
    static void paddingMessage(PASSTHRU_MSG &smsg);
    
    bool sendFlowControlMessage(TimeType Timeout);

    J2534ChannelISO15765 &mChannel;
    uint32_t mMaskPid;
    uint32_t mPatternPid;
    uint32_t mFlowControlPid;
    
    int mBs;
    int mStmin;
    
    unsigned int mSequence;
    std::vector<PASSTHRU_MSG> mMessages;
    int mMessageBs;
    TransferState mState;
    off_t mOffset;
};


/*
 *
 * J2534Device
 *
 */

J2534DeviceImpl::J2534DeviceImpl(const J2534LibraryImplPtr &library, unsigned long device) : mLibrary(library), mDeviceID(device) {

}

J2534DeviceImpl::~J2534DeviceImpl() {
    long ret = mLibrary->mFcts.passThruClose(mDeviceID);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
}

J2534ChannelPtr J2534DeviceImpl::connect(unsigned long ProtocolID, unsigned long Flags, unsigned long BaudRate) {
    unsigned long ChannelID;
    long ret;
    if (ProtocolID == ISO15765) {
        ret = mLibrary->mFcts.passThruConnect(mDeviceID, CAN, Flags, BaudRate, &ChannelID);
    } else {
        ret = mLibrary->mFcts.passThruConnect(mDeviceID, ProtocolID, Flags, BaudRate, &ChannelID);
    }
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
    
    J2534ChannelPtr retChannel = std::make_shared<J2534ChannelImpl>(std::static_pointer_cast<J2534DeviceImpl>(shared_from_this()), ChannelID);
    if (ProtocolID == ISO15765) {
        retChannel = createISO15765Channel(retChannel);
    }
    return retChannel;
}

void J2534DeviceImpl::setProgrammingVoltage(unsigned long PinNumber, unsigned long Voltage) {
    long ret = mLibrary->mFcts.passThruSetProgrammingVoltage(mDeviceID, PinNumber, Voltage);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
}

void J2534DeviceImpl::readVersion(char *pFirmwareVersion, char *pDllVersion, char *pApiVersion) {
    long ret = mLibrary->mFcts.passThruReadVersion(mDeviceID, pFirmwareVersion, pDllVersion, pApiVersion);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
}

void J2534DeviceImpl::ioctl(unsigned long IoctlID, void *pInput, void *pOutput) {
    long ret = mLibrary->mFcts.passThruIoctl(mDeviceID, IoctlID, pInput, pOutput);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
}

J2534LibraryPtr J2534DeviceImpl::getLibrary() const {
    return mLibrary;
}

/*
 *
 * ISO15765Transfer
 *
 */
static uint32_t data2pid(const uint8_t *data) {
    uint32_t pid = 0;
    
    pid |= ((0x1F & data[0]) << 24);
    pid |= ((0xFF & data[1]) << 16);
    pid |= ((0xFF & data[2]) << 8);
    pid |= ((0xFF & data[3]) << 0);
    
    return pid;
}

static void pid2Data(uint32_t pid, uint8_t *data) {
    data[0] = (0x1F & (pid >> 24));
    data[1] = (0xFF & (pid >> 16));
    data[2] = (0xFF & (pid >> 8));
    data[3] = (0xFF & (pid >> 0));
}

ISO15765Transfer::ISO15765Transfer(J2534ChannelISO15765 &channel, const PASSTHRU_MSG &pMaskMsg, const PASSTHRU_MSG &pPatternMsg, const PASSTHRU_MSG &pFlowControlMsg):mChannel(channel), mMessages(1), mState(START_STATE) {
    mMaskPid = data2pid(pMaskMsg.Data);
    mPatternPid = data2pid(pPatternMsg.Data);
    mFlowControlPid = data2pid(pFlowControlMsg.Data);
    mBs = mChannel.getBs();
    mStmin = mChannel.getStmin();
    mMessages.resize(1);
}

ISO15765Transfer::~ISO15765Transfer() {
    
}

void ISO15765Transfer::clear() {
    mState = START_STATE;
    mOffset = 0;
}

#define IS_SF(d) (((d & 0xF0) >> 4) == 0)
#define IS_FF(d) (((d & 0xF0) >> 4) == 1)
#define IS_CF(d) (((d & 0xF0) >> 4) == 2)
#define IS_FC(d) (((d & 0xF0) >> 4) == 3)
#define GET_MS(d) (d & 0x0F)

#define J2534_DATA_OFFSET 4
#define CAN_DATA_SIZE 8
#define J2534_PCI_SIZE 1
#define J2534_LENGTH_SIZE 1
#define J2534_BS_SIZE 1
#define J2534_STMIN_SIZE 1

ISO15765Transfer::PCIFrameName ISO15765Transfer::getFrameName(uint8_t pci) {
    if(IS_SF(pci)) {
        return SingleFrame;
    } else if(IS_FF(pci)) {
        return FirstFrame;
    } else if(IS_CF(pci)) {
        return ConsecutiveFrame;
    } else if(IS_FC(pci)) {
        return FlowControl;
    } else {
        return UnknownFrame;
    }
}

uint8_t ISO15765Transfer::getPci(PCIFrameName frameName) {
    if(frameName == SingleFrame) {
        return (0x0 << 4);
    } else if(frameName == FirstFrame) {
        return (0x1 << 4);
    } else if(frameName == ConsecutiveFrame) {
        return (0x2 << 4);
    } else if(frameName == FlowControl) {
        return (0x3 << 4);
    } else {
        return (0xf << 4);
    }
}

size_t ISO15765Transfer::getRemainingSize(const PASSTHRU_MSG &msg, off_t offset) {
    size_t ret = msg.DataSize - offset;
    if(ret > 7) {
        ret = 7;
    }
    return ret;
}

void ISO15765Transfer::prepareSentMessageHeaders(PASSTHRU_MSG &out_msg, const PASSTHRU_MSG &in_msg) {
    out_msg.ProtocolID = CAN;
    out_msg.RxStatus = 0;
    out_msg.TxFlags = in_msg.TxFlags & ~(ISO15765_FRAME_PAD|ISO15765_ADDR_TYPE);
    out_msg.Timestamp = 0;
    out_msg.DataSize = 0;
    out_msg.ExtraDataIndex = 0;
    
    // Copy the PID
    memcpy(&(out_msg.Data[0]), &(in_msg.Data[0]), J2534_DATA_OFFSET);
}

void ISO15765Transfer::prepareReceivedMessageHeaders(PASSTHRU_MSG &out_msg, const PASSTHRU_MSG &in_msg) {
    out_msg.ProtocolID = ISO15765;
    out_msg.RxStatus = in_msg.RxStatus;
    out_msg.TxFlags = 0;
    out_msg.Timestamp = 0;
    out_msg.DataSize = 0;
    out_msg.ExtraDataIndex = 0;
    
    // Copy the PID
    memcpy(&(out_msg.Data[0]), &(in_msg.Data[0]), J2534_DATA_OFFSET);
}

void ISO15765Transfer::paddingMessage(PASSTHRU_MSG &smsg) {
    for(int i = smsg.DataSize; i < CAN_DATA_SIZE + J2534_DATA_OFFSET; ++i) {
        smsg.Data[i] = '\0';
    }
    smsg.DataSize = CAN_DATA_SIZE + J2534_DATA_OFFSET;
}

bool ISO15765Transfer::writeMsg(const PASSTHRU_MSG &msg, TimeType Timeout) {
    int stmin = 0;
    PASSTHRU_MSG &tmp_msg = mMessages[0];
    
    // Set Deadline
    std::chrono::time_point<std::chrono::steady_clock> deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(Timeout);
    
    // Sanity checks
    if(msg.DataSize < J2534_DATA_OFFSET) {
         throw J2534FunctionException(ERR_INVALID_MSG);
    }
    
    if(mState != START_STATE) {
        LOG_DEBUG("Wrong state");
        goto fail;
    }
    
    while(msg.DataSize > (size_t)mOffset) {
        Timeout = (std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())).count();
        if(Timeout <= 0) {
            return false;
        }
        
        if(mState == START_STATE) {
            mOffset = J2534_DATA_OFFSET;
            mSequence = 0;
            prepareSentMessageHeaders(tmp_msg, msg);
            
            // Compute
            PCIFrameName frameName = SingleFrame;
            size_t size = getRemainingSize(msg, mOffset);
            
            if(size < (msg.DataSize - mOffset)) {
                frameName = FirstFrame;
            }
            
            // Fill the buffer
            if(frameName == FirstFrame) {
                LOG_DEBUG("Write FirstFrame");
                size_t fullsize = msg.DataSize - mOffset;
                tmp_msg.Data[J2534_DATA_OFFSET] = (getPci(frameName) & 0xF0)| ((fullsize >> 8) & 0x0F);
                tmp_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE] = (fullsize & 0xFF);
                size = CAN_DATA_SIZE - J2534_PCI_SIZE - J2534_LENGTH_SIZE;
                mSequence++;
                tmp_msg.DataSize = J2534_DATA_OFFSET + J2534_PCI_SIZE + J2534_LENGTH_SIZE + size;
                memcpy(&(tmp_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE + J2534_LENGTH_SIZE]), &(msg.Data[mOffset]), size);
            } else {
                LOG_DEBUG("Write SingleFrame");
                tmp_msg.Data[J2534_DATA_OFFSET] = (getPci(frameName) & 0xF0)| (size & 0x0F);
                tmp_msg.DataSize = J2534_DATA_OFFSET + J2534_PCI_SIZE + size;
                memcpy(&(tmp_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE]), &(msg.Data[mOffset]), size);
            }
            
            mOffset += size;
            
            // Padding
            if(msg.TxFlags & ISO15765_FRAME_PAD) {
                paddingMessage(tmp_msg);
            }
            
            if(mChannel.mChannel->writeMsgs(mMessages, Timeout) != 1) {
                LOG_DEBUG("Can't write message %d", frameName);
                goto fail;
            }
            mState = FLOW_CONTROL_STATE;
        } else if (mState == FLOW_CONTROL_STATE) {
            LOG_DEBUG("Wait for flow control");
            if(mChannel.mChannel->readMsgs(mMessages, Timeout) != 1) {
                LOG_DEBUG("Can't read flow control message");
                goto fail;
            }
            if(tmp_msg.DataSize < J2534_DATA_OFFSET) {
                LOG_DEBUG("Invalid flow control message size");
                goto fail;
            }
            if((data2pid(tmp_msg.Data) & mMaskPid) != mPatternPid) {
                LOG_DEBUG("Incorrect PID");
                goto fail;
            }
            PCIFrameName frameName = getFrameName(tmp_msg.Data[J2534_DATA_OFFSET]);
            if(frameName != FlowControl) {
                LOG_DEBUG("Invalid frame type %d (Need %d)", frameName, FlowControl);
                goto fail;
            }
            
            // Get block information
            mMessageBs = tmp_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE];
            stmin = tmp_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE + J2534_BS_SIZE];
            
            std::this_thread::sleep_for(std::chrono::milliseconds(stmin));
            
            mState = BLOCK_STATE;
        } else if (mState == BLOCK_STATE) {
            LOG_DEBUG("Write block %d", mSequence);
            prepareSentMessageHeaders(tmp_msg, msg);
            
            // Compute
            PCIFrameName frameName = ConsecutiveFrame;
            size_t size = getRemainingSize(msg, mOffset);
            
            // Fill the buffer
            tmp_msg.Data[J2534_DATA_OFFSET] = (getPci(frameName) & 0xF0)| ((mSequence++) & 0x0F);
            tmp_msg.DataSize = J2534_DATA_OFFSET + J2534_PCI_SIZE + size;
            memcpy(&(tmp_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE]), &(msg.Data[mOffset]), size);
            
            mOffset += size;
            
            // Padding
            if(msg.TxFlags & ISO15765_FRAME_PAD) {
                paddingMessage(tmp_msg);
            }
            
            // Write the message
            if(mChannel.mChannel->writeMsgs(mMessages, Timeout) != 1) {
                LOG_DEBUG("Can't write message");
                goto fail;
            }
            
            // End of the block ?
            if(--mMessageBs == 0) {
                mState = FLOW_CONTROL_STATE;
            }
            
            if(mState == BLOCK_STATE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(stmin));
            }
        } else {
            LOG_DEBUG("Wrong state");
            goto fail;
        }
    }
    
    LOG_DEBUG("Message sent !!");
    clear();
    return true;
    
fail:
    clear();
    return false;
}

bool ISO15765Transfer::readMsg(const PASSTHRU_MSG &in_msg, PASSTHRU_MSG &out_msg, TimeType Timeout) {
    PASSTHRU_MSG &read_msg = mMessages[0];
    if(in_msg.DataSize < J2534_DATA_OFFSET) {
        LOG_DEBUG("Invalid flow control message size");
        goto fail;
    }
    if((data2pid(in_msg.Data) & mMaskPid) != mPatternPid) {
        LOG_DEBUG("Incorrect PID");
        goto fail;
    }
    {
        PCIFrameName frameName = getFrameName(in_msg.Data[J2534_DATA_OFFSET]);
        if(mState == START_STATE) {
            prepareReceivedMessageHeaders(read_msg, in_msg);
            mOffset = J2534_DATA_OFFSET;
            mSequence = 0;
            
            if(frameName == SingleFrame) {
                LOG_DEBUG("Receiving SingleFrame");
                size_t size = in_msg.Data[J2534_DATA_OFFSET] & 0x0F;
                read_msg.DataSize = J2534_DATA_OFFSET + size;
                memcpy(&(read_msg.Data[mOffset]), &(in_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE]), size);
                
                mOffset += size;
            } else if(frameName == FirstFrame) {
                LOG_DEBUG("Receiving FirstFrame");
                size_t fullsize = ((in_msg.Data[J2534_DATA_OFFSET] & 0x0F) << 8) | (in_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE] & 0xFF);
                read_msg.DataSize = J2534_DATA_OFFSET + fullsize;
                size_t size = CAN_DATA_SIZE - J2534_PCI_SIZE - J2534_LENGTH_SIZE;
                memcpy(&(read_msg.Data[mOffset]), &(in_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE + J2534_LENGTH_SIZE]), size);
                
                mSequence++;
                mOffset += size;
                
                if(!sendFlowControlMessage(Timeout)) {
                    LOG_DEBUG("Can't send flow control message");
                    goto fail;
                }

                mState = BLOCK_STATE;
            } else {
                LOG_DEBUG("Invalid frame type %d", frameName);
                goto fail;
            }
        } else if(mState == BLOCK_STATE) {
            unsigned int seq = (in_msg.Data[J2534_DATA_OFFSET]) & 0xF;
            if (seq != (mSequence % 0x10)) {
                LOG_DEBUG("Wrong sequence number %d (Need %d)", seq, mSequence);
                goto fail;
            }
            
            size_t size = getRemainingSize(read_msg, mOffset);
            memcpy(&(read_msg.Data[mOffset]), &(in_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE]), size);
            
            mSequence++;
            mOffset += size;
            
            if(--mMessageBs == 0) {
                if(!sendFlowControlMessage(Timeout)) {
                    LOG_DEBUG("Can't send flow control message");
                    goto fail;
                }
            }
        } else {
            LOG_DEBUG("Wrong state");
            goto fail;
        }
        
        if((size_t)mOffset >= read_msg.DataSize) {
            memcpy(&out_msg, &read_msg, sizeof(PASSTHRU_MSG));
            LOG_DEBUG("Message received !!");
            clear();
            return true;
        }
    }
    return false;
    
fail:
    clear();
    return false;
}

bool ISO15765Transfer::sendFlowControlMessage(TimeType Timeout) {
    std::vector<PASSTHRU_MSG> messages(1);
    messages.resize(1);
    PASSTHRU_MSG &tmp_msg = messages[0];
    
    tmp_msg.ProtocolID = CAN;
    tmp_msg.RxStatus = 0;
    tmp_msg.TxFlags = 0;
    tmp_msg.Timestamp = 0;
    tmp_msg.DataSize = J2534_DATA_OFFSET + J2534_PCI_SIZE + J2534_BS_SIZE + J2534_STMIN_SIZE;
    tmp_msg.ExtraDataIndex = 0;
    
    pid2Data(mFlowControlPid, tmp_msg.Data);
    tmp_msg.Data[J2534_DATA_OFFSET] = getPci(FlowControl);
    tmp_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE] = mBs;
    tmp_msg.Data[J2534_DATA_OFFSET + J2534_PCI_SIZE + J2534_BS_SIZE] = mStmin;
    mMessageBs = mBs;
    
    LOG_DEBUG("Sending flow control");
    if(mChannel.mChannel->writeMsgs(messages, Timeout) != 1) {
        return false;
    }
    return true;
}

uint32_t ISO15765Transfer::getMaskPid() {
    return mMaskPid;
}

uint32_t ISO15765Transfer::getPatternPid() {
    return mPatternPid;
}

uint32_t ISO15765Transfer::getFlowControlPid() {
    return mFlowControlPid;
}

/*
 *
 * J2534ChannelISO15765
 *
 */

J2534ChannelISO15765::J2534ChannelISO15765(const J2534ChannelPtr &channel): mChannel(channel) {
    
}

J2534ChannelISO15765::~J2534ChannelISO15765() {
    
}

int J2534ChannelISO15765::getBs() const {
    return bs;
}
    
int J2534ChannelISO15765::getStmin() const {
    return stmin;
}

std::shared_ptr<ISO15765Transfer> J2534ChannelISO15765::getTransferByFlowControl(const PASSTHRU_MSG &msg) {
    uint32_t pid = data2pid(msg.Data);
    std::map<MessageFilter, std::shared_ptr<ISO15765Transfer>>::iterator it = std::find_if(mTransfers.begin(), mTransfers.end(), [&](const std::pair<MessageFilter, std::shared_ptr<ISO15765Transfer>> &it) {
        return it.second->getFlowControlPid() == pid;
    });
    if (it != mTransfers.end())  {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<ISO15765Transfer> J2534ChannelISO15765::getTransferByPattern(const PASSTHRU_MSG &msg) {
    uint32_t pid = data2pid(msg.Data);
    std::map<MessageFilter, std::shared_ptr<ISO15765Transfer>>::iterator it = std::find_if(mTransfers.begin(), mTransfers.end(), [&](const std::pair<MessageFilter, std::shared_ptr<ISO15765Transfer>> &it) {
        return it.second->getPatternPid() == (pid & it.second->getMaskPid());
    });
    if (it != mTransfers.end())  {
        return it->second;
    }
    return nullptr;
}

J2534ChannelISO15765::MessageFilter J2534ChannelISO15765::startMsgFilter(unsigned long FilterType, PASSTHRU_MSG *pMaskMsg, PASSTHRU_MSG *pPatternMsg,
                                     PASSTHRU_MSG *pFlowControlMsg) {
    if(FilterType == FLOW_CONTROL_FILTER) {
        if (pMaskMsg == NULL || pPatternMsg == NULL || pFlowControlMsg == NULL) {
            throw J2534FunctionException(ERR_NULLPARAMETER);
        }
        MessageFilter mf = mChannel->startMsgFilter(PASS_FILTER, pMaskMsg, pPatternMsg, NULL);
        mTransfers.insert(std::pair<MessageFilter, std::shared_ptr<ISO15765Transfer>>(mf, std::make_shared<ISO15765Transfer>(*this, *pMaskMsg, *pPatternMsg, *pFlowControlMsg)));
        return mf;
    } else {
        return mChannel->startMsgFilter(FilterType, pMaskMsg, pPatternMsg, pFlowControlMsg);
    }
}

void J2534ChannelISO15765::stopMsgFilter(MessageFilter messageFilter) {
    mChannel->stopMsgFilter(messageFilter);
    mTransfers.erase(messageFilter);
}

size_t J2534ChannelISO15765::readMsgs(std::vector <PASSTHRU_MSG> &msgs, TimeType Timeout) {
    size_t i = 0;
    
    std::vector <PASSTHRU_MSG> readMsgs(1);
    readMsgs.resize(1);
    
    std::chrono::time_point<std::chrono::steady_clock> deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(Timeout);
    for(PASSTHRU_MSG &msg: msgs) {
        while(true) {
            Timeout = (std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())).count();
            if(Timeout <= 0) {
                LOG_DEBUG("Timeout");
                return i;
            }
            
            if (mChannel->readMsgs(readMsgs, Timeout) != 1) {
                LOG_DEBUG("Can't read msg");
                return i;
            }
            
            Timeout = (std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())).count();

            // Get transfer
            auto transfer = getTransferByPattern(readMsgs[0]);
            if (transfer) {
                if(transfer->readMsg(readMsgs[0], msg, Timeout)) {
                    i++;
                    break;
                }
            } else {
                LOG_DEBUG("No matching transfer");
            }
        }
    };
    return i;
}

size_t J2534ChannelISO15765::writeMsgs(std::vector <PASSTHRU_MSG> &msgs, TimeType Timeout) {
    size_t i = 0;
    std::chrono::time_point<std::chrono::steady_clock> deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(Timeout);
    for(PASSTHRU_MSG &msg: msgs) {
        Timeout = (std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())).count();
        if(Timeout <= 0) {
            return i;
        }
        auto transfer = getTransferByFlowControl(msg);
        if (transfer) {
            if(transfer->writeMsg(msg, Timeout)) {
                i++;
            } else {
                LOG_DEBUG("Can't write msg");
            }
        } else {
            LOG_DEBUG("Ignore msg");
        }
    };
    return i;
}

void J2534ChannelISO15765::ioctl(unsigned long IoctlID, void *pInput, void *pOutput) {
    if(IoctlID == CLEAR_RX_BUFFER) {
        mChannel->ioctl(IoctlID, pInput, pOutput);
        for (auto& it : mTransfers) {
            it.second->clear();
        }
    } else if(IoctlID == SET_CONFIG) {
        if (pInput == NULL) {
            throw J2534FunctionException(ERR_NULLPARAMETER);
        }
        SCONFIG_LIST *Input = (SCONFIG_LIST *)pInput;
        for (unsigned int i = 0; i < Input->NumOfParams; ++i) {
            SCONFIG *config = &(Input->ConfigPtr[i]);
            if(config->Parameter == ISO15765_BS) {
                bs = config->Value;
            } else if(config->Parameter == ISO15765_STMIN) {
                stmin = config->Value;
            } else {
                SCONFIG_LIST altInput;
                altInput.NumOfParams = 1;
                altInput.ConfigPtr = config;
                mChannel->ioctl(SET_CONFIG, &altInput, NULL);
            }
        }
    } else if(IoctlID == GET_CONFIG) {
        if (pInput == NULL) {
            throw J2534FunctionException(ERR_NULLPARAMETER);
        }
        SCONFIG_LIST *Input = (SCONFIG_LIST *)pInput;
        for (unsigned int i = 0; i < Input->NumOfParams; ++i) {
            SCONFIG *config = &(Input->ConfigPtr[i]);
            if(config->Parameter == ISO15765_BS) {
                config->Value = bs;
            } else if(config->Parameter == ISO15765_STMIN) {
                config->Value = stmin;
            } else {
                SCONFIG_LIST altInput;
                altInput.NumOfParams = 1;
                altInput.ConfigPtr = config;
                mChannel->ioctl(GET_CONFIG, &altInput, NULL);
            }
        }
    } else {
        mChannel->ioctl(IoctlID, pInput, pOutput);
    }
}

J2534Channel::PeriodicMessage J2534ChannelISO15765::startPeriodicMsg(PASSTHRU_MSG *pMsg, TimeType TimeInterval) {
    return mChannel->startPeriodicMsg(pMsg, TimeInterval);
}

void J2534ChannelISO15765::stopPeriodicMsg(PeriodicMessage periodicMessage) {
    mChannel->stopPeriodicMsg(periodicMessage);
}

J2534DevicePtr J2534ChannelISO15765::getDevice() const {
    return mChannel->getDevice();
}


/*
 *
 * J2534ChannelImpl
 *
 */

J2534ChannelImpl::J2534ChannelImpl(const J2534DeviceImplPtr &device, unsigned long channel) : mDevice(device), mChannelID(channel) {

}

J2534ChannelImpl::~J2534ChannelImpl() {
    long ret = mDevice->mLibrary->mFcts.passThruDisconnect(mChannelID);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
}

size_t J2534ChannelImpl::readMsgs(std::vector <PASSTHRU_MSG> &msg, TimeType Timeout) {
    unsigned long tmpNumMsgs = msg.size();
    long ret = mDevice->mLibrary->mFcts.passThruReadMsgs(mChannelID, &msg[0], &tmpNumMsgs, Timeout);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
    return tmpNumMsgs;
}

size_t J2534ChannelImpl::writeMsgs(std::vector <PASSTHRU_MSG> &msg, TimeType Timeout) {
    unsigned long tmpNumMsgs = msg.size();
    long ret = mDevice->mLibrary->mFcts.passThruWriteMsgs(mChannelID, &msg[0], &tmpNumMsgs, Timeout);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
    return tmpNumMsgs;
}

J2534Channel::PeriodicMessage J2534ChannelImpl::startPeriodicMsg(PASSTHRU_MSG *pMsg, TimeType TimeInterval) {
    unsigned long MsgID;
    long ret = mDevice->mLibrary->mFcts.passThruStartPeriodicMsg(mChannelID, pMsg, &MsgID, TimeInterval);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
    return MsgID;
}

void J2534ChannelImpl::stopPeriodicMsg(PeriodicMessage perdiodicMessage) {
    long ret = mDevice->mLibrary->mFcts.passThruStopPeriodicMsg(mChannelID, perdiodicMessage);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
}

J2534Channel::MessageFilter J2534ChannelImpl::startMsgFilter(unsigned long FilterType, PASSTHRU_MSG *pMaskMsg,
                                                         PASSTHRU_MSG *pPatternMsg, PASSTHRU_MSG *pFlowControlMsg) {
    unsigned long FilterID;
    long ret = mDevice->mLibrary->mFcts.passThruStartMsgFilter(mChannelID, FilterType, pMaskMsg, pPatternMsg,
                                                               pFlowControlMsg, &FilterID);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
    return FilterID;
}

void J2534ChannelImpl::stopMsgFilter(MessageFilter messageFilter) {
    long ret = mDevice->mLibrary->mFcts.passThruStopMsgFilter(mChannelID, messageFilter);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
}

void J2534ChannelImpl::ioctl(unsigned long IoctlID, void *pInput, void *pOutput) {
    long ret = mDevice->mLibrary->mFcts.passThruIoctl(mChannelID, IoctlID, pInput, pOutput);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
}

J2534DevicePtr J2534ChannelImpl::getDevice() const {
    return mDevice;
}

/*
 *
 * J2534Library
 *
 */
 
#ifdef _WIN32
#define LOAD_FCT(proxy_handle, name, type, dest) { \
    dest = (type)GetProcAddress(proxy_handle, #name); \
    if(dest == NULL) { \
        throw J2534LoadException("Can't load \"#name\" function from library"); \
    } \
}
#else // _WIN32
#define LOAD_FCT(proxy_handle, name, type, dest) { \
    dest = (type)dlsym(proxy_handle, #name); \
    if(dest == NULL) { \
        throw J2534LoadException("Can't load \"#name\" function from library"); \
    } \
}
#endif // _WIN32

J2534LibraryImpl::J2534LibraryImpl(const char *library) {
#ifdef _WIN32
    mModule = LoadLibraryA(library);
#else // _WIN32
    mModule = dlopen(library, RTLD_LAZY);
#endif // _WIN32
    if (!mModule) {
        throw J2534LoadException("Can't load library");
    }
    try {
        LOAD_FCT(mModule, PassThruOpen, PTOPEN, mFcts.passThruOpen);
        LOAD_FCT(mModule, PassThruClose, PTCLOSE, mFcts.passThruClose);
        LOAD_FCT(mModule, PassThruConnect, PTCONNECT, mFcts.passThruConnect);
        LOAD_FCT(mModule, PassThruDisconnect, PTDISCONNECT, mFcts.passThruDisconnect);
        LOAD_FCT(mModule, PassThruReadMsgs, PTREADMSGS, mFcts.passThruReadMsgs);
        LOAD_FCT(mModule, PassThruWriteMsgs, PTWRITEMSGS, mFcts.passThruWriteMsgs);
        LOAD_FCT(mModule, PassThruStartPeriodicMsg, PTSTARTPERIODICMSG, mFcts.passThruStartPeriodicMsg);
        LOAD_FCT(mModule, PassThruStopPeriodicMsg, PTSTOPPERIODICMSG, mFcts.passThruStopPeriodicMsg);
        LOAD_FCT(mModule, PassThruStartMsgFilter, PTSTARTMSGFILTER, mFcts.passThruStartMsgFilter);
        LOAD_FCT(mModule, PassThruStopMsgFilter, PTSTOPMSGFILTER, mFcts.passThruStopMsgFilter);
        LOAD_FCT(mModule, PassThruSetProgrammingVoltage, PTSETPROGRAMMINGVOLTAGE, mFcts.passThruSetProgrammingVoltage);
        LOAD_FCT(mModule, PassThruReadVersion, PTREADVERSION, mFcts.passThruReadVersion);
        LOAD_FCT(mModule, PassThruGetLastError, PTGETLASTERROR, mFcts.passThruGetLastError);
        LOAD_FCT(mModule, PassThruIoctl, PTIOCTL, mFcts.passThruIoctl);
    } catch (J2534LoadException &exception) {
#ifdef _WIN32
        FreeLibrary(mModule);
#else // _WIN32
        dlclose(mModule);
#endif // _WIN32
        throw exception;
    }
}

J2534LibraryImpl::~J2534LibraryImpl() {
#ifdef _WIN32
    FreeLibrary(mModule);
#else // _WIN32
    dlclose(mModule);
#endif // _WIN32
}

J2534DevicePtr J2534LibraryImpl::open(void *pName) {
    unsigned long DeviceID;
    long ret = mFcts.passThruOpen(pName, &DeviceID);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
    return std::make_shared<J2534DeviceImpl>(std::static_pointer_cast<J2534LibraryImpl>(shared_from_this()), DeviceID);
}

void J2534LibraryImpl::getLastError(char *pErrorDescription) {
    long ret = mFcts.passThruGetLastError(pErrorDescription);
    if (ret != STATUS_NOERROR) {
        throw J2534FunctionException(ret);
    }
}

J2534_API_API J2534LibraryPtr loadJ2534Library(const char *library) {
    return std::make_shared<J2534LibraryImpl>(library);
}

J2534_API_API J2534ChannelPtr createISO15765Channel(const J2534ChannelPtr &channel) {
    return std::make_shared<J2534ChannelISO15765>(channel);
}


/*
 * False destructors
 */
 
J2534Library::~J2534Library() {
}

J2534Device::~J2534Device() {    
}

J2534Channel::~J2534Channel() {
}

