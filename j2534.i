%module(directors="1") j2534
%begin %{
#include <cmath>
%}
%{
#include <j2534_v0404.h>
#include <j2534.h>

%}

// Int
%include "stdint.i"

//
// Exceptions
//
%include "exception.i"

%include <j2534_v0404.h>

%exception {
    try {
        $action
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}

%extend J2534LoadException {
  const char *__str__() {
    return self->what();
  }
};

%extend J2534FunctionException {
  const char *__str__() {
    return self->what();
  }
};

%catches(J2534LoadException) J2534Library::J2534;
%catches(J2534FunctionException) J2534Library::open;
%catches(J2534FunctionException) J2534Library::close;
%catches(J2534FunctionException) J2534Library::connect;
%catches(J2534FunctionException) J2534Library::disconnect;
%catches(J2534FunctionException) J2534Library::readMsgs;
%catches(J2534FunctionException) J2534Library::writeMsgs;
%catches(J2534FunctionException) J2534Library::startPeriodicMsg;
%catches(J2534FunctionException) J2534Library::stopPeriodicMsg;
%catches(J2534FunctionException) J2534Library::startMsgFilter;
%catches(J2534FunctionException) J2534Library::stopMsgFilter;
%catches(J2534FunctionException) J2534Library::setProgrammingVoltage;
%catches(J2534FunctionException) J2534Library::readVersion;
%catches(J2534FunctionException) J2534Library::getLastError;
%catches(J2534FunctionException) J2534Library::ioctl;

//
// Specific behaviours
//
%include "cstring.i"
%cstring_bounded_output(char *pFirmwareVersion, 80);
%cstring_bounded_output(char *pDllVersion, 80);
%cstring_bounded_output(char *pApiVersion, 80);
void J2534Library::readVersion(unsigned long DeviceID, char *pFirmwareVersion, char *pDllVersion, char *pApiVersion);

//
// Vectors
//
%include "std_vector.i"
namespace std {
   %template(vector_passthru_msg) vector<PASSTHRU_MSG>;
};

//
// Shared pointers
//
%include <std_shared_ptr.i>
%shared_ptr(J2534Library)
%shared_ptr(J2534Device)
%shared_ptr(J2534Channel)

%include <j2534.h>