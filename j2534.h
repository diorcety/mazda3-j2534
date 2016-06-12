#pragma once

#ifndef _J2534_H
#define _J2534_H

#include <memory>
#include "j2534_v0404.h"

/*
 * OS
 */
#include <exception>
#include <vector>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else // _WIN32

#include <dlfcn.h>

#endif // _WIN32

/*
 * DLL
 */
#ifdef _WIN32
#ifndef SWIG
#ifdef J2534_EXPORTS
#define J2534_API_API __declspec(dllexport)
#else
#define J2534_API_API __declspec(dllimport)
#endif // J2534_EXPORTS
#else // SWIG
#define J2534_API_API
#endif // SWIG
#else // _WIN32
#define J2534_API_API
#endif // _WIN32

/*
 * Exceptions
 */

class J2534_API_API J2534LoadException : public std::exception {
public:
    J2534LoadException(const char *error);

    virtual const char *what() const noexcept;

private:
    std::string mError;
};


class J2534_API_API J2534FunctionException : public std::exception {
public:
    J2534FunctionException(long code);

    long code() const;

    virtual const char *what() const noexcept;

private:
    long mCode;
};


/*
 * Classes
 */

class J2534Device;

typedef std::shared_ptr <J2534Device> J2534DevicePtr;
typedef std::weak_ptr <J2534Device> J2534DeviceWeakPtr;

class J2534Channel;

typedef std::shared_ptr <J2534Channel> J2534ChannelPtr;
typedef std::weak_ptr <J2534Channel> J2534ChannelWeakPtr;

class J2534Library;

typedef std::shared_ptr <J2534Library> J2534LibraryPtr;
typedef std::weak_ptr <J2534Library> J2534LibraryWeakPtr;

class J2534_API_API J2534Device : public std::enable_shared_from_this<J2534Device> {
public:
    virtual ~J2534Device() = 0;

    virtual J2534ChannelPtr connect(unsigned long ProtocolID, unsigned long Flags, unsigned long BaudRate) = 0;

    virtual void setProgrammingVoltage(unsigned long PinNumber, unsigned long Voltage) = 0;

    virtual void readVersion(char *pFirmwareVersion, char *pDllVersion, char *pApiVersion) = 0;

    virtual void ioctl(unsigned long IoctlID, void *pInput, void *pOutput) = 0;

    virtual J2534LibraryPtr getLibrary() const = 0;
};

class J2534_API_API J2534Channel : public std::enable_shared_from_this<J2534Channel> {
public:
    typedef unsigned long TimeType;
    typedef unsigned long PeriodicMessage;
    typedef unsigned long MessageFilter;
    
    virtual ~J2534Channel() = 0;

    virtual size_t readMsgs(std::vector <PASSTHRU_MSG> &msgs, TimeType Timeout) = 0;

    virtual size_t writeMsgs(std::vector <PASSTHRU_MSG> &msgs, TimeType Timeout) = 0;

    virtual PeriodicMessage startPeriodicMsg(PASSTHRU_MSG *pMsg, TimeType TimeInterval) = 0;

    virtual void stopPeriodicMsg(PeriodicMessage periodicMessage) = 0;

    virtual MessageFilter startMsgFilter(unsigned long FilterType, PASSTHRU_MSG *pMaskMsg, PASSTHRU_MSG *pPatternMsg,
                                         PASSTHRU_MSG *pFlowControlMsg) = 0;

    virtual void stopMsgFilter(MessageFilter messageFilter) = 0;

    virtual void ioctl(unsigned long IoctlID, void *pInput, void *pOutput) = 0;

    virtual J2534DevicePtr getDevice() const = 0;
};

class J2534_API_API J2534Library : public std::enable_shared_from_this<J2534Library> {
public:
    virtual ~J2534Library() = 0;

    virtual J2534DevicePtr open(void *pName) = 0;

    virtual void getLastError(char *pErrorDescription) = 0;
};

J2534_API_API J2534LibraryPtr loadJ2534Library(const char *library);
J2534_API_API J2534ChannelPtr createISO15765Channel(const J2534ChannelPtr &channel);

#endif //_J2534_H
