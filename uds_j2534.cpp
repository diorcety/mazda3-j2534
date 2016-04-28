#include "uds_j2534.h"


UDS_J2534::UDS_J2534(J2534ChannelPtr channel, UDS_PID tester, UDS_PID ecu, unsigned long protocolID, unsigned long flags) :
        UDS(tester, ecu), mChannel(channel), mProtocolID(protocolID), mFlags(flags) {

}

UDS_J2534::~UDS_J2534() {

}

UDSMessagePtr UDS_J2534::send(const UDSMessagePtr request, int timeout) {
    PASSTHRU_MSG MaskMsg;
    PASSTHRU_MSG PatternMsg;
    PASSTHRU_MSG FlowControlMsg;
    J2534Channel::MessageFilter messageFilter = mChannel->startMsgFilter(FLOW_CONTROL_FILTER, &MaskMsg, &PatternMsg, &FlowControlMsg);

    UDSMessagePtr ret;
    try {
        std::vector<PASSTHRU_MSG> msg;
        msg.reserve(1);

        msg[0].ProtocolID = mProtocolID;
        msg[0].TxFlags = mFlags;
        const std::vector<uint8_t> &data = request->getData();
        msg[0].Data[0] = 0x1F & (mEcu >> 24);
        msg[0].Data[1] = 0xFF & (mEcu >> 16);
        msg[0].Data[2] = 0xFF & (mEcu >> 8);
        msg[0].Data[3] = 0xFF & (mEcu >> 0);
        memcpy(&msg[0].Data[4], &data[0], data.size());

        if(mChannel->readMsgs(msg, timeout) == 0 || !(msg[0].RxStatus & START_OF_MESSAGE)) {
            throw UDSException("Invalid state");
        }

        if(mChannel->readMsgs(msg, timeout) == 0) {
            throw UDSException("Invalid state");
        }

        if(msg[0].DataSize < 4) {
            throw UDSException("Invalid data size");
        }
        ret = buildMessage(&msg[0].Data[4], msg[0].DataSize - 4);
        mChannel->stopMsgFilter(messageFilter);
    } catch(...) {
        mChannel->stopMsgFilter(messageFilter);
        throw;
    }
    return ret;
}