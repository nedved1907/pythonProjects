{ *****************************************************************************
  *
  * Sentinel LDK Licensing API
  *
  * Copyright (C) 2021 Thales Group. All rights reserved.
  *
  ***************************************************************************** }

{$A8,B-,C-,D-,E-,F-,G+,H+,I-,J-,K-,L-,M-,N+,O+,P+,Q-,R-,S-,T-,U-,V+,W-,X+,Y-,Z1}

unit hasp_unit;

interface


uses
  Winapi.Windows,
  System.Win.Crtl,
  System.SysUtils;


{------------------------------------------------------------------------------
  basic types (for platform compatibility)
 ------------------------------------------------------------------------------}

type
  hasp_u64_t = int64;
  hasp_s64_t = int64;
  hasp_u32_t = longword;
  hasp_s32_t = longint;
  hasp_u16_t = word;
  hasp_s16_t = smallint;
  hasp_u8_t  = byte;
  hasp_s8_t  = shortint;

{-----------------------------------------------------------------------------
  hasp_ types
 -----------------------------------------------------------------------------}

type
  hasp_status_t       = hasp_u32_t;  // raw error code
  hasp_size_t         = hasp_u32_t;  // length
  hasp_handle_t       = hasp_u32_t;  // connection handle
  hasp_feature_t      = hasp_u32_t;  // feature id
  hasp_fileid_t       = hasp_u32_t;  // memory file id
  hasp_time_t         = hasp_u64_t;  // time, seconds since Jan-01-1970 0:00 GMT
  hasp_vendor_code_t  = pointer;     // contains the vendor code

{-----------------------------------------------------------------------------}

const
  { hasp_get_info() / hasp_get_sessioninfo() format to get update info (C2V) }
  HASP_UPDATEINFO = '<haspformat format="updateinfo"/>';

  { format to retrieve a small update info (C2V) }
  HASP_FASTUPDATEINFO = '<haspformat format="fastupdateinfo"/>';

  { hasp_get_info() / hasp_get_sessioninfo() format to get session info }
  HASP_SESSIONINFO = '<haspformat format="sessioninfo"/>';

  { hasp_get_info() / hasp_get_sessioninfo() format to get key/hardware info }
  HASP_KEYINFO = '<haspformat format="keyinfo"/>';

  HASP_RECIPIENT = '<haspformat root="location">'#13#10 +
                   '  <license_manager>'#13#10 +
                   '    <attribute name="id" />'#13#10 +
                   '    <attribute name="time" />'#13#10 +
                   '    <element name="hostname" />'#13#10 +
                   '    <element name="version" />'#13#10 +
                   '    <element name="host_fingerprint" />'#13#10 +
                   '  </license_manager>'#13#10 +
                   '</haspformat>'#13#10;

{------------------------------------------------------------------------------
  Feature ID constants
 ------------------------------------------------------------------------------}

  // AND-mask used to identify feature type
  HASP_FEATURETYPE_MASK = $ffff0000;

  // After AND-ing with HASP_FEATURETYPE_MASK feature type contain this value.
  HASP_PROGNUM_FEATURETYPE = $ffff0000;

  // AND-mask used to extract program number from feature id if
  // program number feature.
  HASP_PROGNUM_MASK = $000000ff;

{------------------------------------------------------------------------------
  prognum options mask

  AND-mask used to identify prognum options:
      - HASP_PROGNUM_OPT_NO_LOCAL
      - HASP_PROGNUM_OPT_NO_REMOTE
      - HASP_PROGNUM_OPT_PROCESS
      - HASP_PROGNUM_OPT_CLASSIC
      - HASP_PROGNUM_OPT_TS

   3 bits of the mask are reserved for future extensions and currently unused.
   Initialize them to zero.
}

const
  { Invalid handle value for hasp_login() and hasp_login_scope() functions }
  HASP_INVALID_HANDLE_VALUE = 0;

  { Minimum block size for hasp_encrypt() and hasp_decrypt() functions. }
  HASP_MIN_BLOCK_SIZE = 16;

  { Minimum block size for hasp_legacy_encrypt() and hasp_legacy_decrypt() legacy functions. }
  HASP_MIN_BLOCK_SIZE_LEGACY = 8;


  HASP_PROGNUM_OPT_MASK = $0000ff00;

  { Disable local license search }
  HASP_PROGNUM_OPT_NO_LOCAL = $00008000;

  { Disable network license search }
  HASP_PROGNUM_OPT_NO_REMOTE = $00004000;

  { Sets session count of network licenses to per-process }
  HASP_PROGNUM_OPT_PROCESS = $00002000;

  { Enables the API to access "classic" (HASP4 or earlier) keys }
  HASP_PROGNUM_OPT_CLASSIC = $00001000;

  { Presence of Terminal Services gets ignored }
  HASP_PROGNUM_OPT_TS = $00000800;

  { Present in every hardware key. }
  HASP_DEFAULT_FID = 0;

  { Present in every hardware HASP key. }
  HASP_PROGNUM_DEFAULT_FID = (HASP_DEFAULT_FID or HASP_PROGNUM_FEATURETYPE);

{------------------------------------------------------------------------------
  hasp_file_ids - Memory file id constants
 ------------------------------------------------------------------------------}

  { File id for HASP4 compatible memory contents w/o license data area }
  HASP_FILEID_MAIN = $fff0;

  {(Dummy) file id for HASP4 RTC chip memory contents }
  HASP_FILEID_TIME = $fff1;

  { (Dummy) file id for license data area of memory contents }
  HASP_FILEID_LICENSE = $0000fff2;

  { File ID for Sentinel HASP secure writable memory. }
  HASP_FILEID_RW = $0000fff4;

  { File ID for Sentinel HASP secure read only memory }
  HASP_FILEID_RO = $0000fff5;


{------------------------------------------------------------------------------
  hasp_error_codes - Error code constants
 ------------------------------------------------------------------------------}

const
    HASP_STATUS_OK = 0;               { Request successfully completed }
    HASP_MEM_RANGE = 1;               { Request exceeds memory range of a HASP file }
    HASP_INV_PROGNUM_OPT = 2;         { Legacy HASP HL Run-time API: Unknown/Invalid Feature ID option }
    HASP_INSUF_MEM = 3;               { System is out of memory }
    HASP_TMOF = 4;                    { Too many open Features/login sessions }
    HASP_ACCESS_DENIED = 5;           { Access to Feature, HASP protection key or functionality denied }
    HASP_INCOMPAT_FEATURE = 6;        { Legacy decryption function cannot work on Feature }
    HASP_CONTAINER_NOT_FOUND = 7;     { DEPRECATED }
    HASP_HASP_NOT_FOUND = 7;          { Sentinel HASP protection key not available }
    HASP_TOO_SHORT = 8;               { Encrypted/decrypted data length too short to execute function call }
    HASP_INV_HND = 9;                 { Invalid login handle passed to function }
    HASP_INV_FILEID = 10;             { Specified File ID not recognized by API }
    HASP_OLD_DRIVER = 11;             { Installed driver or daemon too old to execute function }
    HASP_NO_TIME = 12;                { Real-time clock (rtc) not available }
    HASP_SYS_ERR = 13;                { Generic error from host system call }
    HASP_NO_DRIVER = 14;              { Required driver not installed }
    HASP_INV_FORMAT = 15;             { Unrecognized file format for update }
    HASP_REQ_NOT_SUPP = 16;           { Unable to execute function in this context }
    HASP_INV_UPDATE_OBJ = 17;         { Binary data passed to function does not contain valid update }
    HASP_KEYID_NOT_FOUND = 18;        { HASP protection key not found }
    HASP_INV_UPDATE_DATA = 19;        { Required XML tags not found; Contents in binary data are missing }
    HASP_INV_UPDATE_NOTSUPP = 20;     { Update request not supported by Sentinel HASP protection key }
    HASP_INV_UPDATE_CNTR = 21;        { Update counter set incorrectly }
    HASP_INV_VCODE = 22;              { Invalid Vendor Code passed }
    HASP_ENC_NOT_SUPP = 23;           { Sentinel HASP protection key does not support encryption type }
    HASP_INV_TIME = 24;               { Passed time value outside supported value range }
    HASP_NO_BATTERY_POWER = 25;       { Real-time clock battery out of power }
    HASP_NO_ACK_SPACE = 26;           { Acknowledge data requested by update, but ack_data parameter is null }
    HASP_TS_DETECTED = 27;            { Program running on a terminal server }
    HASP_FEATURE_TYPE_NOT_IMPL = 28;  { Requested Feature type not implemented }
    HASP_UNKNOWN_ALG = 29;            { Unknown algorithm used in H2R/V2C file }
    HASP_INV_SIG = 30;                { Signature verification operation failed }
    HASP_FEATURE_NOT_FOUND = 31;      { Requested Feature not available }
    HASP_NO_LOG = 32;                 { Access log not enabled }
    HASP_LOCAL_COMM_ERR = 33;         { Communication error between API and local HASP License Manager }
    HASP_UNKNOWN_VCODE = 34;          { Vendor Code not recognized by API }
    HASP_INV_SPEC = 35;               { Invalid XML specification }
    HASP_INV_SCOPE = 36;              { Invalid XML scope }
    HASP_TOO_MANY_KEYS = 37;          { Too many Sentinel HASP protection keys currently connected }
    HASP_TOO_MANY_USERS = 38;         { Too many concurrent user sessions currently connected }
    HASP_BROKEN_SESSION = 39;         { Session been interrupted }
    HASP_REMOTE_COMM_ERR = 40;        { Communication error between local and remote HASP License Managers }
    HASP_FEATURE_EXPIRED = 41;        { Feature expired }
    HASP_OLD_LM = 42;                 { HASP License Manager version too old }
    HASP_DEVICE_ERR = 43;             { Input/Output error occurred }
    HASP_UPDATE_BLOCKED = 44;         { Update installation not permitted; This update was already applied }
    HASP_TIME_ERR = 45;               { System time has been tampered with }
    HASP_SCHAN_ERR = 46;              { Communication error occurred in secure channel }
    HASP_STORAGE_CORRUPT = 47;        { Corrupt data exists in secure storage area of HASP SL protection key }
    HASP_NO_VLIB = 48;                { Unable to find Vendor library }
    HASP_INV_VLIB = 49;               { Unable to load Vendor library }
    HASP_SCOPE_RESULTS_EMPTY = 50;    { Unable to locate any Feature matching scope }
    HASP_VM_DETECTED = 51;            { Program running on a virtual machine }
    HASP_HARDWARE_MODIFIED = 52;      { HASP SL key incompatible }
    HASP_USER_DENIED = 53;            { Login denied because of user restrictions }
    HASP_UPDATE_TOO_OLD = 54;         { out of sequence }
    HASP_UPDATE_TOO_NEW = 55;         { Update to old }
    HASP_OLD_VLIB = 56;               { Old vlib }
    HASP_UPLOAD_ERROR = 57;           { Upload via ACC failed, e.g. because of illegal format }
    HASP_INV_RECIPIENT = 58;          { Invalid XML "recipient" parameter }
    HASP_INV_DETACH_ACTION = 59;      { Invalid XML "action" parameter }
    HASP_TOO_MANY_PRODUCTS = 60;      { scope does not specify a unique product }
    HASP_INV_PRODUCT = 61;            { Invalid Product information }
    HASP_UNKNOWN_RECIPIENT = 62;      { Unknown Recipient }
    HASP_INV_DURATION = 63;           { Invalid Duration }
    HASP_CLONE_DETECTED = 64;         { Cloned HASP SL secure storage detected }
    HASP_UPDATE_ALREADY_ADDED = 65;   { Specified v2c update already installed in the LLM }
    HASP_HASP_INACTIVE = 66;          { Specified Hasp Id is in Inactive state }
    HASP_NO_DETACHABLE_FEATURE = 67;  { No detachable feature exists }
    HASP_NO_DEATCHABLE_FEATURE = 67;  { No detachable feature exists (typo kept for compatibility) }
    HASP_TOO_MANY_HOSTS = 68;         { scope does not specify a unique Host }
    HASP_REHOST_NOT_ALLOWED = 69;     { Rehost is not allowed for any license }
    HASP_LICENSE_REHOSTED = 70;       { License is rehosted to other machine }
    HASP_REHOST_ALREADY_APPLIED = 71; { Old rehost license try to apply }
    HASP_CANNOT_READ_FILE = 72;       { File not found or access denied }
    HASP_EXTENSION_NOT_ALLOWED = 73;  { Extension of license not allowed as number of detached licenses is greater than current concurrency count }
    HASP_DETACH_DISABLED = 74;        { Detach of license not allowed as product contains VM disabled feature and host machine is a virtual machine }
    HASP_REHOST_DISABLED = 75;        { Rehost of license not allowed as container contains VM disabled feature and host machine is a virtual machine }
    HASP_DETACHED_LICENSE_FOUND = 76; { Format SL-AdminMode or migrate SL-Legacy to SL-AdminMode not allowed as container has detached license }
    HASP_RECIPIENT_OLD_LM = 77;       { Recipient of the requested operation is older than expected}
    HASP_SECURE_STORE_ID_MISMATCH=78; { Secure storage ID mismatch }
    HASP_DUPLICATE_HOSTNAME = 79;     { Duplicate Hostname found while key contains Hostname Fingerprinting }
    HASP_MISSING_LM = 80;             { The Sentinel License Manager is required for this operation }
    HASP_FEATURE_INSUFFICIENT_EXECUTION_COUNT = 81; { You are attempting to consume multiple executions during log in to a Feature. However, the license for the Feature does not contain enough remaining executions }
	HASP_INCOMPATIBLE_PLATFORM = 82;  { Attempting to perform an operation not compatible with target platform }
    HASP_HASP_DISABLED = 83;          { The key is disabled due to suspected tampering }
    HASP_SHARING_VIOLATION = 84;      { The key is inaccessible due to sharing } 
    HASP_KILLED_SESSION = 85;         { The session was killed due a network malfunction or manually from ACC } 
    HASP_VS_DETECTED = 86;            { Program running on a virtual storage } 
    HASP_IDENTITY_REQUIRED = 87;      { An identity is required } 
    HASP_IDENTITY_UNAUTHENTICATED = 88; { The identity is not authenticated } 
    HASP_IDENTITY_DISABLED = 89;      { The identity is disabled } 
    HASP_IDENTITY_DENIED = 90;        { The identity doesn't have enough permission for the operation } 
    HASP_IDENTITY_SHARING_VIOLATION = 91; { A session for this identity from a different machine already exists } 
    HASP_IDENTITY_TOO_MANY_MACHINES = 92; { The maximum number of machines usable by the identity was reached } 
    HASP_IDENTITY_SERVER_NOT_READY = 93; { The server is not ready to authenticate }
    HASP_UPDATE_OUT_OF_SYNC = 94;     { Trying to install a V2C file with an update counter that is out of sync with update counter in the Sentinel protection key. The server is not ready to authenticate }
    HASP_REMOTE_SHARING_VIOLATION = 95; { Multiple attempts to access the key from remote with a proxy }
    HASP_CLOUD_SESSION_OCCUPIED_REMOTELY = 96; { The session was released because the seat was requested from a different location }
    HASP_NO_API_DYLIB = 400;          { API dispatcher: API for this Vendor Code was not found }
    HASP_INV_API_DYLIB = 401;         { API dispatcher: Unable to load API; DLL possibly corrupt? }
    HASP_INVALID_OBJECT = 500;        { C++ API: Object incorrectly initialized }
    HASP_INVALID_PARAMETER = 501;     { C++ API: Invalid function parameter }
    HASP_ALREADY_LOGGED_IN = 502;     { C++ API: Logging in twice to the same object }
    HASP_ALREADY_LOGGED_OUT = 503;    { C++ API: Logging out twice of the same object }
    HASP_OPERATION_FAILED = 525;      { .NET API: Incorrect use of system or platform }
    HASP_NO_EXTBLOCK = 600;           { Internal use: no classic memory extension block available }
    HASP_INV_PORT_TYPE = 650;         { Internal use: invalid port type }
    HASP_INV_PORT = 651;              { Internal use: invalid port value }
    HASP_NOT_IMPL = 698;              { Requested function not implemented }
    HASP_INT_ERR = 699;               { Internal error occurred in API }
    HASP_FIRST_HELPER = 2001;         { Reserved for HASP helper libraries }
    HASP_FIRST_HASP_ACT = 3001;       { Reserved for HASP Activation API }
    HASP_NEXT_FREE_VALUES = 7001;     {  }

{------------------------------------------------------------------------------
  The Basic API
 ------------------------------------------------------------------------------}

{-----------------------------------------------------------------------------
  Login into a feature.

  This function establishes a context (logs into a feature).
  hasp_login() also does the connection handling. There is one connection
  (secure channel) per API object. The last logout closes the channel.
  (see hasp_logout())
  When logging into a "classic" feature, the secure channel is not used.

  feature_id       - unique identifier of the feature,
                     With "classic" features (see \ref HASP_FEATURETYPE_MASK),
                     8 bits are reserved for legacy options (see \ref HASP_PROGNUM_OPT_MASK,
                     currently 5 bits are used):
                      - only local
                      - only remote
                      - login is counted per process ID
                      - disable terminal server check
                      - enable access to old (HASP3/HASP4) keys
  vendor_code      - pointer to the vendor blob
  handle           - pointer to the resulting session handle

  return           status code
                   - HASP_STATUS_OK         - the request completed successfully
                   - HASP_FEATURE_NOT_FOUND - the requested feature isn't available
                   - HASP_NOT_IMPL          - the type of feature isn't implemented
                   - HASP_INV_CLASSIC_OPT   - unknown classic option requested (HASP_PROGNUM_OPT_MASK)
                   - HASP_TMOF              - too many open handles
                   - HASP_INSUF_MEM         - out of memory
				   - HASP_INV_VCODE			- Invalid Vendor Code
                   - HASP_NO_DRIVER			- Driver not installed
                   - HASP_NO_VLIB			- Vendor library cannot be found
                   - HASP_INV_VLIB			- Vendor library cannot be loaded
                   - HASP_OLD_DRIVER		- Driver too old
                   - HASP_UNKNOWN_VCODE		- Vendor Code not recognized
                   - HASP_FEATURE_EXPIRED	- Feature has expired
                   - HASP_TOO_MANY_USERS	- Too many users currently connected
                   - HASP_OLD_LM			- Sentinel License Manager version too old
                   - HASP_DEVICE_ERR		- Input/Output error in  Sentinel SL/SL-AdminMode/SL-UserMode secure storage, 
											  OR in case of a Sentinel HL key, USB communication error
                   - HASP_TIME_ERR			- System time has been tampered with
                   - HASP_HARDWARE_MODIFIED	- Sentinel SL key incompatible with machine hardware; 
											  Sentinel SL key is locked to different hardware
                   - HASP_TS_DETECTED		- Program is running on a Terminal Server
                   - HASP_LOCAL_COMM_ERR	- Communication error between API and local  Sentinel License Manager
                   - HASP_REMOTE_COMM_ERR	- Communication error between local and remote  Sentinel License Manager
                   - HASP_OLD_VLIB			- Vendor Library version too old
                   - HASP_CLONE_DETECTED	- Cloned Sentinel SL storage detected. Feature unavailable

  For local prognum features, concurrency is not handled and each
  login performs a decrement if it is a counting license.

  Network prognum features just use the old HASPLM login logic with all
  drawbacks. There is only support for concurrent usage of one server
  (global server address).
}
function hasp_login( feature_id  : hasp_feature_t;
                     vendor_code : hasp_vendor_code_t;
                     var handle  : hasp_handle_t ) : hasp_status_t; stdcall;


{-----------------------------------------------------------------------------
  Logout.

  Logs out from a session and frees all allocated memory for the session. If it
  was the last session from this API, the connection to the LLM is shut down.

  handle       - session handle of session to log out from

  return     status code
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle

}

function hasp_logout(handle : hasp_handle_t) : hasp_status_t; stdcall;

{------------------------------------------------------------------------------
  Encrypt a buffer.

  This function encrypts a buffer.

  handle      - session handle
  buffer      - pointer to the buffer to be encrypted
  length      - size in bytes of the buffer to be encrypted (16 bytes minimum)

  return     status code
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_NOT_IMPL          - the functionality for this feature type isn't implemented
               - HASP_TOO_SHORT         - the length of the data to be encrypted is too short
               - HASP_ENC_NOT_SUPP      - encryption type not supported by the hardware
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available anymore
			   - HASP_SCHAN_ERR			- Communication error occurred in secure channel OR Sentinel HL Firmware too old
										  (update to 3.25 or later)
               - HASP_BROKEN_SESSION	- Session has been interrupted
               - HASP_LOCAL_COMM_ERR	- Communication error between API and local Sentinel License Manager
               - HASP_REMOTE_COMM_ERR	- Communication error between local and remote Sentinel License Manager

  If the encryption fails (e.g. key removed in-between) the data pointed to
  by buffer is unmodified.
}

function hasp_encrypt( handle : hasp_handle_t;
                       var buffer;
                       length : hasp_size_t) : hasp_status_t; stdcall;


{------------------------------------------------------------------------------
  Decrypt a buffer.

  This function decrypts a buffer. This is the reverse operation of the
  hasp_encrypt() function. See hasp_encrypt() for more information.

  handle      - session handle
  buffer      - pointer to the buffer to be decrypted
  length      - size in bytes of the buffer to be decrypted (16 bytes minimum)

  return     status code
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_NOT_IMPL          - the functionality for this feature type isn't implemented
               - HASP_TOO_SHORT         - the length of the data to be decrypted is too short
               - HASP_ENC_NOT_SUPP      - encryption type not supported by the hardware
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available anymore
			   - HASP_SCHAN_ERR			- Communication error occurred in secure channel OR Sentinel HL Firmware too old
										  (update to 3.25 or later)
               - HASP_BROKEN_SESSION	- Session has been interrupted
               - HASP_LOCAL_COMM_ERR	- Communication error between API and local Sentinel License Manager
               - HASP_REMOTE_COMM_ERR	- Communication error between local and remote Sentinel License Manager

 If the decryption fails (e.g. key removed in-between) the data
 pointed to by buffer is unmodified.
}

function hasp_decrypt ( handle : hasp_handle_t;
                        var buffer;
                        length : hasp_size_t)  : hasp_status_t; stdcall;


{------------------------------------------------------------------------------
  Read from key memory.

  This function is used to read from the key memory.

  handle       - session handle
  fileid       - id of the file to read (memory descriptor)
  offset       - file offset in the file
  length       - length
  buffer       - result of the read operation

  return     status code.
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_NOT_IMPL          - the functionality for this feature type isn't implemented
               - HASP_INV_FILEID        - unknown fileid
               - HASP_MEM_RANGE         - attempt to read beyond eom
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available anymore
			   - HASP_DEVICE_ERR		- Input/Output error in Sentinel SL/SL-AdminMode/SL-UserMode secure storage, 
										  OR in case of a Sentinel HL key, USB communication error
			   - HASP_SCHAN_ERR			- Communication error occurred in secure channel OR Sentinel HL Firmware too old
										  (update to 3.25 or later)
               - HASP_BROKEN_SESSION	- Session has been interrupted
               - HASP_LOCAL_COMM_ERR	- Communication error between API and local Sentinel License Manager
               - HASP_REMOTE_COMM_ERR	- Communication error between local and remote Sentinel License Manager
}

function hasp_read( handle : hasp_handle_t;
                    fileid : hasp_fileid_t;
                    offset : hasp_size_t;
                    length : hasp_size_t;
                    var buffer) : hasp_status_t;  stdcall;


{------------------------------------------------------------------------------
  Write to key memory.

  This function is used to write to the key memory. Depending on the provided
  session handle (either logged into the default feature or any other feature),
  write access to the license data memory (HASP_FILEID_LICENSE) is not permitted.

  handle       - session handle
  fileid       - id of the file to write
  offset       - file offset in the file
  length       - length
  buffer       - what to write

  return     status code.
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_NOT_IMPL          - the functionality for this feature type isn't implemented
               - HASP_INV_FILEID        - unknown fileid
               - HASP_MEM_RANGE         - attempt to write beyond eom
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available anymore
			   - HASP_DEVICE_ERR		- Input/Output error in Sentinel SL/SL-AdminMode/SL-UserMode secure storage, 
										  OR in case of a Sentinel HL key, USB communication error
			   - HASP_SCHAN_ERR			- Communication error occurred in secure channel OR Sentinel HL Firmware too old
										  (update to 3.25 or later)
               - HASP_BROKEN_SESSION	- Session has been interrupted
               - HASP_LOCAL_COMM_ERR	- Communication error between API and local Sentinel License Manager
               - HASP_REMOTE_COMM_ERR	- Communication error between local and remote Sentinel License Manager


}

function hasp_write ( handle : hasp_handle_t;
                      fileid : hasp_fileid_t;
                      offset : hasp_size_t;
                      length : hasp_size_t;
                      var buffer) : hasp_status_t;  stdcall;

{------------------------------------------------------------------------------
  Get memory size.

  This function is used to determine the memory size.

  handle       - session handle
  fileid       - id of the file to query
  size         - pointer to the resulting file size

  result     status code
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_NOT_IMPL          - the functionality for this feature type isn't implemented
               - HASP_INV_FILEID        - unknown fileid
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available any more
			   - HASP_DEVICE_ERR		- Input/Output error in Sentinel SL/SL-AdminMode/SL-UserMode secure storage, 
										  OR in case of a Sentinel HL key, USB communication error
			   - HASP_SCHAN_ERR			- Communication error occurred in secure channel OR Sentinel HL Firmware too old
										  (update to 3.25 or later)
               - HASP_BROKEN_SESSION	- Session has been interrupted
               - HASP_LOCAL_COMM_ERR	- Communication error between API and local Sentinel License Manager
               - HASP_REMOTE_COMM_ERR	- Communication error between local and remote Sentinel License Manager


}

function hasp_get_size( handle   : hasp_handle_t;
                        fileid   : hasp_fileid_t;
                        var size : hasp_size_t) : hasp_status_t;  stdcall;

{------------------------------------------------------------------------------
  Read current time from a time key.

  This function reads the current time from a time key.
  The time will be returned in seconds since Jan-01-1970 0:00 GMT.

  remark:
    The general purpose of this function is not related to
    licensing, but to get reliable timestamps which are independent
    from the system clock.

  handle       - session handle
  time         - pointer to the actual time

  return     status code
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_NOT_IMPL          - the functionality for this feature type isn't implemented
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available anymore
               - HASP_NO_TIME           - RTC not available
			   - HASP_NO_BATTERY_POWER	- Real-time clock has run out of power
			   - HASP_SCHAN_ERR			- Communication error occurred in secure channel OR Sentinel HL Firmware too old
										  (update to 3.25 or later)
               - HASP_BROKEN_SESSION	- Session has been interrupted
               - HASP_LOCAL_COMM_ERR	- Communication error between API and local Sentinel License Manager
               - HASP_REMOTE_COMM_ERR	- Communication error between local and remote Sentinel License Manager


}

function hasp_get_rtc( handle   : hasp_handle_t;
                       var time : hasp_time_t) : hasp_status_t;  stdcall;


{------------------------------------------------------------------------------
  Legacy HASP functionality for backward compatibility
 ------------------------------------------------------------------------------}

{------------------------------------------------------------------------------
  Legacy HASP4 compatible encryption function.

  handle       - session handle
  buffer       - pointer to the buffer to be encrypted
  length       - size in bytes of the buffer  (8 bytes minimum)

  return     status code
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_TOO_SHORT         - the length of the data to be encrypted is too short
               - HASP_ENC_NOT_SUPP      - encryption type not supported by the hardware
               - HASP_INCOMPAT_FEATURE  - classic encryption is not available for this feature
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available anymore

  The handle must have been obtained by calling hasp_login() with
  a prognum feature id.

  If the encryption fails (e.g. key removed in-between) the data
  pointed to by buffer is undefined.
}

function hasp_legacy_encrypt(handle : hasp_handle_t;
                             var buffer;
                             length : hasp_size_t ) : hasp_status_t; stdcall;


{------------------------------------------------------------------------------
  Legacy HASP4 compatible decryption function.

  handle       - session handle
  buffer       - pointer to the buffer to be decrypted
  length       - size in bytes of the buffer (8 bytes minimum)

  return     status code
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_TOO_SHORT         - the length of the data to be decrypted is too short
               - HASP_ENC_NOT_SUPP      - encryption type not supported by the hardware
               - HASP_INCOMPAT_FEATURE  - classic decryption is not available for this feature
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available anymore

  The handle must have been obtained by calling \ref hasp_login() with
  a prognum feature id.

  If the decryption fails (e.g. key removed in-between) the data
  pointed to by buffer is undefined.
}

function hasp_legacy_decrypt ( handle : hasp_handle_t;
                               var buffer;
                               length : hasp_size_t ) : hasp_status_t; stdcall;


{------------------------------------------------------------------------------
  Write to HASP4 compatible real time clock

  handle       - session handle
  new_time     - time value to be set

  return     status code
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_INCOMPAT_FEATURE  - functionality is not available for this feature
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available anymore
               - HASP_NO_TIME           - RTC not available

  Note: The handle must have been obtained by calling hasp_login() with
        a prognum feature id.
}

function hasp_legacy_set_rtc( handle   : hasp_handle_t;
                              new_time : hasp_time_t ) : hasp_status_t; stdcall;


{------------------------------------------------------------------------------
  Set the LM idle time.

  handle       - session handle
  idle_time    - the idle time in minutes

  return      status code
               - HASP_STATUS_OK         - the request completed successfully
               - HASP_INV_HND           - invalid input handle
               - HASP_INCOMPAT_FEATURE  - changing the idletime is not available for this feature
               - HASP_FEATURE_NOT_FOUND - the requested feature isn't available anymore
               - HASP_REQ_NOT_SUPP      - attempt to set the idle time for a local license

  Note: The handle must have been obtained by calling hasp_login() with
        a prognum feature id.
}

function hasp_legacy_set_idletime ( handle    : hasp_handle_t;
                                    idle_time : hasp_u16_t ) : hasp_status_t; stdcall;


{------------------------------------------------------------------------------
  Extended HASP HL API
 ------------------------------------------------------------------------------

  The extended API consists of functions which provide extended functionality.
  This advanced functionality is sometimes necessary, and addresses the
  "advanced" user.

 ------------------------------------------------------------------------------
  Get information in a session context.

  Memory for the information is allocated by this function and has to be
  freed by the hasp_free() function.

  handle       - session handle
  format       - XML definition of the output data structure
  info         - pointer to the returned information (XML list)

  return     status code
               - HASP_STATUS_OK  		- the request completed successfully
               - HASP_INV_HND    		- handle not active
               - HASP_INV_FORMAT 		- unrecognised format
			   - HASP_DEVICE_ERR		- Input/Output error in Sentinel SL/SL-AdminMode/SL-UserMode secure storage, OR in case 
										  of a Sentinel HL key, USB communication error
			   - HASP_SCHAN_ERR			- Communication error occurred in secure channel OR Sentinel HL Firmware too old
										  (update to 3.25 or later)
               - HASP_BROKEN_SESSION	- Session has been interrupted
               - HASP_LOCAL_COMM_ERR	- Communication error between API and local Sentinel License Manager
               - HASP_REMOTE_COMM_ERR	- Communication error between local and remote Sentinel License Manager
			   - HASP_TIME_ERR			- System time has been tampered with
}

function hasp_get_sessioninfo( handle   : hasp_handle_t;
                               format   : PAnsiChar;
                               var info : PAnsiChar) : hasp_status_t; stdcall;


{------------------------------------------------------------------------------
  Free resources allocated by hasp_get_sessioninfo

  This function must be called to free the resources
  allocated by hasp_get_sessioninfo.

  info   -  pointer to the resources to be freed
}

procedure hasp_free (info : pointer); stdcall;


{------------------------------------------------------------------------------
  Write an update.

  This function writes update information. The update blob contains all
  necessary data to perform the update: Where to write (in which "container",
  e.g. dongle), the necessary access data (passwords) and of course the
  update itself. The function returns in an acknowledge blob, which is
  signed/encrypted by the updated instance and contains a proof that this
  update has been succeeded. Memory for the acknowledge blob is allocated by
  the API and has to be freed by the programmer (see hasp_free()).

  update_data      - pointer to the complete update data.
  ack_data         - pointer to a buffer to get the acknowledge data.

  return     status code
			   - HASP_STATUS_OK				-  Request was successfully completed
               - HASP_KEYID_NOT_FOUND		-  The Sentinel protection key was not found
               - HASP_INV_UPDATE_DATA		- Required XML tags not found; Contents in binary data are missing or invalid
               - HASP_INV_UPDATE_NOTSUPP	- Update request is not supported by Sentinel protection key
               - HASP_INV_UPDATE_CNTR		- Update counter not set correctly
               - HASP_INSUF_MEM				- Out of memory
               - HASP_DEVICE_ERR			- Input/Output error in Sentinel SL secure storage, OR in case of a Sentinel HL key,
											  USB communication error
               - HASP_LOCAL_COMM_ERR		- Communication error between API and local Sentinel License Manager
               - HASP_REMOTE_COMM_ERR		- Communication error between local and remote Sentinel License Manager
               - HASP_NO_ACK_SPACE			- Acknowledge data requested by the update, but ack_data parameter is NULL
               - HASP_UNKNOWN_ALG			- Unknown algorithm used in V2C file
               - HASP_INV_SIG				- Signature verification failed
               - HASP_TOO_MANY_KEYS			- Too many Sentinel protection keys match the scope
               - HASP_HARDWARE_MODIFIED		- Conflict between Sentinel SL key data and machine hardware data;Sentinel SL key 
											  locked to different hardware
               - HASP_UPDATE_TOO_OLD		- Trying to install a V2C file with an update counter that is out of sequence with the 
											  update counter in the Sentinelprotection key. The values of the update counter in the
											  file are lower than those in the Sentinel protection key
               - HASP_UPDATE_TOO_NEW		- Trying to install a V2C file with an update counter that is out of sequence with the
											  update counter in the Sentinel protection key. The first value in the file is more 
											  than 1 greater than the value in the Sentinel protection key
               - HASP_UNKNOWN_RECIPIENT		- In case of an H2R:Update can only be applied to the Recipient specified in hasp_detach(), 
											  not to this machine
               - HASP_HASP_INACTIVE			- Inactive Sentinel SL-AdminMode/SL-UserMode key-id
               - HASP_UPDATE_ALREADY_ADDED	- Sentinel SL-AdminMode/SL-UserMode V2C update(s) already applied
               - HASP_REHOST_ALREADY_APPLIED- In case of SL-AdminMode/SL-UserMode H2H: Specified H2H already applied
               - HASP_LICENSE_REHOSTED		- In case of SL-AdminMode/SL-UserMode V2C: Specified V2C already rehosted to another 
											  host
}

function hasp_update ( update_data  : PAnsiChar;
                       var ack_data : PAnsiChar ) : hasp_status_t;
                       stdcall;


{------------------------------------------------------------------------------
  Utility functions
 ------------------------------------------------------------------------------}

{------------------------------------------------------------------------------
  Converts a date and time value to hasptime (the number of elapsed seconds 
  since January 1 1970).

  day          - input day
  month        - input month
  year         - input year
  hour         - input hour
  minute       - input minute
  second       - input second
  time         - pointer to put result

  return     status code
               - HASP_STATUS_OK  - the request completed successfully
               - HASP_INV_TIME   - time outside of the supported range
}
function hasp_datetime_to_hasptime ( day, month, year,
                                     hour, minute, second : cardinal;
                                     var time : hasp_time_t ) : hasp_status_t; stdcall;


{------------------------------------------------------------------------------
  Convert time type into broken up time

  time         - pointer to put result
  day          - pointer to day
  month        - pointer to month
  year         - pointer to year
  hour         - pointer to hour
  minute       - pointer to minute
  second       - pointer to second

  return     status code
               - HASP_STATUS_OK  - the request completed successfully
               - HASP_INV_TIME   - time outside of the supported range
}

function hasp_hasptime_to_datetime ( time : hasp_time_t;
                                     var day, month, year,
                                     hour, minute, second : cardinal) : hasp_status_t; stdcall;

{------------------------------------------------------------------------------
  Feature ID convention
 ------------------------------------------------------------------------------

  Feature ids are 32bits wide. If the upper 16 bit contain the value indicated
  by HASP_PROGNUM_FEATURETYPE, the feature defines a prognum feature.

  For prognum features there are some options encoded in the feature id.
  These include

  - HASP_PROGNUM_OPT_NO_LOCAL
    Don't search for a license locally. "Remote-only"

  - HASP_PROGNUM_OPT_NO_REMOTE
    Don't search for a license on the network. "Local-only"

  - HASP_PROGNUM_OPT_PROCESS
    In case, a license is found in the network, count license usage per
    process instead of per workstation.

  - HASP_PROGNUM_OPT_TS
    Don't detect whether the program is running on a remote screen
    on a terminal server.

  - HASP_PROGNUM_OPT_CLASSIC
    The API by default only searches for HASPHL keys. When this option
    is set, it also searches for HASP3/HASP4 keys.
}

function hasp_login_scope(feature_id  : hasp_feature_t;
                          scope       : PAnsiChar;
                          vendor_code : hasp_vendor_code_t;
                          var handle  : hasp_handle_t) : hasp_status_t; stdcall;
{------------------------------------------------------------------------------
Retrieves information about system components, according to customizable search parameters, and presents it according to 
customizable formats.
 
Sentinel Licensing API Usage Notes
You do not need to be logged in to a Sentinel Feature in order to use this function.
 
 This function is used to specify conditions about where to search for information. In addition, it enables you to specify 
 conditions about the format in which the retrieved information is presented. If retrieved information is appropriately formatted, 
 it can be used as a template in the hasp_login_scope() function.
 
 The requisite Vendor Codes are stored in a VendorCodes folder in your system. Without the correct Vendor Code, the function call 
 cannot succeed.
 
 This function allocates memory for the information it retrieves. To release allocated memory resources, use the 
 hasp_free function.
 
 This function cannot be used to retrieve legacy HASP Features.
 
	- scope       - Definition of the data that is to be searched, in XML format. 
					For more information, see the accompanying Sentinel Licensing API help documentation
	- format      - Definition of the format in which the data is to be displayed, in XML format. 
					For more information, see the accompanying Sentinel Licensing API help documentation
	- vendor_code - Pointer to the Vendor Code
	- info        - Pointer to the information that is retrieved, in XML format

  return      status code
              - HASP_STATUS_OK         		- the request completed successfully
			  - HASP_SCOPE_RESULTS_EMPTY	- Unable to locate a Feature matching the scope
              - HASP_INSUF_MEM				- Out of memory
              - HASP_INV_VCODE				- Invalid Vendor Code
              - HASP_UNKNOWN_VCODE			- Vendor Code not recognized
              - HASP_INVALID_PARAMETER		- Scope or format string too long (max. length 32 kb)
              - HASP_DEVICE_ERR				- Input/Output error in Sentinel SL/SL-AdminMode/SL-UserMode secure storage, 
											  OR in case of a Sentinel HL key, USB communication error
              - HASP_LOCAL_COMM_ERR			- Communication error between API and local Sentinel License Manager
              - HASP_REMOTE_COMM_ERR		- Communication error between local and remote Sentinel License Manager
              - HASP_INV_FORMAT				- Unrecognised format string
              - HASP_INV_SCOPE				- Unrecognised scope string
              - HASP_BROKEN_SESSION			- Session has been interrupted
              - HASP_TOO_MANY_KEYS			- In case of getting C2V:Too many Sentinel protection keys match the scope
			  - HASP_TOO_MANY_HOSTS			- In case of getting host fingerprint: Too many Sentinel License Manager match the 
											  scope
              - HASP_HASP_INACTIVE			- In case of getting C2V:Inactive Sentinel SL-AdminMode/SL-UserMode key-id
}
function hasp_get_info(scope          : PAnsiChar;
                       format         : PAnsiChar;
                       vendor_code    : hasp_vendor_code_t;
                       var info       : PAnsiChar) : hasp_status_t; stdcall;

{------------------------------------------------------------------------------
 Detaches or cancels an attached license, according to customizable parameters.

 Starting from Sentinel LDK version 6.0, the "hasp_detach" API has been deprecated.
 Thales recommends that user should use the "hasp_transfer" API to perform the detach/cancel actions.
 This API has been retained for backward compatibility.

 Sentinel Licensing API Usage Notes

 You do not need to be logged in to a  Sentinel Feature in order to use this function.

 This function is used to detach a license for a Product (i.e. all Sentinel Features and Memory files which belong to this Product) from a Sentinel SL Protection key. The function returns a H2R file which must then be applied on the recipient machine using hasp_update() or the ACC.

 This function only works with Sentinel SL Protection Keys; Sentinel HL Protection Keys are ignored.

 This function can also be used on the recipient machine to cancel an attached license.
 In this case, the recipient parameter is ignored and should be set to NULL.
 For cancelling, the function returns a R2H file which must be applied on the host machine using hasp_update() or the ACC.
 If the detached Product is already expired, no R2H file will be returned.

 The required Vendor Codes are stored in a VendorCodes folder in your system. Without the correct Vendor Code, the function
 call cannot succeed.

	- detach_action	 	- Parameters for the operation, in XML format.
						  For more information, see the accompanying Sentinel Licensing API help documentation.
	- scope       		- Search parameters for the Product that is to be detached
	- vc          		- Pointer to the Vendor Code
	- recipient   		- Definition in XML format of the recipient computer, on which the detached Product will be installed.
						  This information can be retrieved using either hasp_get_info or hasp_get_sessioninfo together with
						  the format specifier HASP_RECIPIENT. Set to NULL if an attached protection key is cancelled.
	- info        		- Pointer to the information that is retrieved, in XML format. This information is a V2C,
						  which can then be installed on the recipient computer via hasp_update.
						  Use @a hasp_free to release this pointer after use.
 *
  return     status code
                    - HASP_STATUS_OK			-  Request was successfully completed
                    - HASP_INV_DETACH_ACTION	- Invalid XML "detach_action" parameter
                    - HASP_INV_RECIPIENT		- Invalid XML "recipient" parameter
                    - HASP_TOO_MANY_PRODUCTS	- Scope for hasp_detach does not specify a unique Parameter
                    - HASP_TOO_MANY_USERS		- Too many users currently connected, or: at least one detachable
												  Feature does not have enough network seats available
                    - HASP_ACCESS_DENIED		- Request cannot be processed due to ACC restrictions
                    - HASP_FEATURE_EXPIRED		- All detachable Features are expired
                    - HASP_INV_PRODUCT			- Invalid Product information
                    - HASP_INV_DURATION			- In the case of a new detachable license, duration exceeds maximum allowed
												  OR, in the case of a detachable license extension, expiration date earlier
												  than original date or too short (if an existing detached Product is extended,
												  and the new expiration date is earlier than the original expiration date)
                    - HASP_INSUF_MEM			- Out of memory
                    - HASP_DEVICE_ERR			- Input/Output error in Sentinel SL secure storage, OR in case of a Sentinel HL key,
												  USB communication error
                    - HASP_LOCAL_COMM_ERR		- Communication error between API and local Sentinel License Manager
                    - HASP_REMOTE_COMM_ERR		- Communication error between local and remote Sentinel License Manager
 }


function hasp_detach(detach_action    : PAnsiChar;
                     scope            : PAnsiChar;
                     vc               : hasp_vendor_code_t;
                     recipient        : PAnsiChar;
                     var info         : PAnsiChar) : hasp_status_t; stdcall;

{------------------------------------------------------------------------------
 Deprecate the above API "hasp_detach()" , This API performs same functionalities as "hasp_detach()" does. 
 Along with this,"hasp_transfer()" API is used to rehost the SL-AdminMode/SL-UserMode V2C from one machine to another machine.
 
 Sentinel Licensing API Usage Notes
 
 You do not need to be logged in to a Sentinel Feature in order to use this function.
 
 This function is used to perform the following task as per its "action" parameter.
	
	for "detach" action: detach a license for a Product (i.e. all Sentinel Features and Memory files which belong to this Product)
						 from a Sentinel SL/SL-AdminMode/SL-UserMode key. The function returns a buffer which should be saved as 
						 H2R file.
	for "cancel" action: This action runs on the recipient machine to cancel an attached license. In this case, the recipient 
						  parameter is ignored and  should be set to NULL. For cancelling, the function returns a buffer which 
						  must be applied on the host machine using hasp_update() or ACC If the detached Product is already expired,
						  no buffer will be returned.
	for "rehost" action: create a transferable a license for given container (i.e. all Sentinel Features and Memory files which 
						 belong to this container) from SL-AdminMode/ SL-UserMode Protection key. The function returns buffer on 
						 success which must be saved as V2C file. hasp_update() or ACC is used to apply this on destination machine.
 
 This function only works with Sentinel SL/SL-AdminMode/SL-UserMode Protection Keys; Sentinel HL Protection Keys are ignored.

 The required Vendor Codes are stored in a VendorCodes folder in your system. Without the correct Vendor Code, the function call 
 cannot succeed.
 
	- action      - Parameters for the operation, in XML format. For more information, see the accompanying Sentinel Licensing API 
					help documentation.
	- scope       - Search parameters for the container-id that is to be re-hosted. For more information, see the accompanying 
					Sentinel Licensing API help documentation.
	- vc          - Pointer to the Vendor Code
	- recipient   - Definition in XML format of the recipient computer,on which the detached Product will be installed.
					This information can be retrieved using either hasp_get_info or hasp_get_sessioninfo together with the format 
					specifier HASP_RECIPIENT.
	- info        - Pointer to the information that is retrieved, in XML format. This information is a V2C, which can then be 
					installed on the destination computer via hasp_update. Use @a hasp_free to release this pointer after use.
	return          status code
                     - HASP_STATUS_OK				- Request was successfully completed
                     - HASP_INV_ACTION				- Invalid XML "action" parameter
                     - HASP_INV_RECIPIENT			- Invalid XML "recipient" parameter
                     - HASP_TOO_MANY_PRODUCTS		- Scope for hasp_transfer for detach action does not specify a unique Parameter
                     - HASP_TOO_MANY_USERS			- Too many users currently connected, or: at least one detachable Feature does 
													  not have enough network seats available
                     - HASP_ACCESS_DENIED			- Request cannot be processed due to ACC restrictions
                     - HASP_FEATURE_EXPIRED			- All detachable Features are expired
                     - HASP_INV_PRODUCT				- Invalid Product information
                     - HASP_INV_DURATION			- In the case of a new detachable license, duration exceeds maximum allowed OR,
													  in the case of a detachable license extension, expiration date earlier than 
													  original date or too short (if an existing detached Product is extended, and 
													  the new expiration date is earlier than the original expiration date)
                     - HASP_TOO_MANY_KEYS			- Scope for hasp_transfer does not specify a unique Parameter
                     - HASP_ACCESS_DENIED			- Request cannot be processed due to ACC restrictions
                     - HASP_INSUF_MEM				- Out of memory
                     - HASP_DEVICE_ERR				- Input/Output error in Sentinel SL/SL-AdminMode/SL-UserMode secure storage, 
													  OR in case of a Sentinel HL key, USB communication error
                     - HASP_LOCAL_COMM_ERR			- Communication error between API and local Sentinel License Manager
                     - HASP_NO_DEATCHABLE_FEATURE	- In case of H2R:No detachable feature found in specified product
                     - HASP_OLD_LM					- Sentinel License Manager is not supported to SL-AdminMode/ SL-UserMode
                     - HASP_HASP_INACTIVE			- SL-AdminMode/SL-UserMode container is inactive
                     - HASP_REHOST_NOT_ALLOWED		- Specified SL-AdminMode/SL-UserMode container is not allowed for rehost
 }
function hasp_transfer(action         : PAnsiChar;
                      scope           : PAnsiChar;
                      vc              : hasp_vendor_code_t;
                      recipient       : PAnsiChar;
                      var info        : PAnsiChar) : hasp_status_t; stdcall;

{------------------------------------------------------------------------------
Retrieves version and build number of the Sentinel library
 
	major_version 	- Pointer to retrieve the major version number
	minor_version 	- Pointer to retrieve the minor version number
	build_server  	- Pointer to retrieve the build server id
	build_number  	- Pointer to retrieve the build number
	vendor_code   	- Pointer to the Vendor Code
 return     status code
				- HASP_STATUS_OK	- Request was successfully completed
 
 Any pointer other than the vendor_code can be NULL if its information is not required.
 }
function hasp_get_version(var major_version : integer;
                          var minor_version : integer;
                          var build_server  : integer;
                          var build_number  : integer;
                          vendor_code       : hasp_vendor_code_t) : hasp_status_t; stdcall;

{------------------------------------------------------------------------------
  Free all resources allocated 
}
function hasp_cleanup() : hasp_status_t; stdcall;

{-----------------------------------------------------------------------------}
  implementation
{-----------------------------------------------------------------------------}

 {$I hasp_helper.inc}

function hasp_login;                stdcall; external;
function hasp_logout;               stdcall; external;
function hasp_encrypt;              stdcall; external;
function hasp_decrypt;              stdcall; external;
function hasp_read;                 stdcall; external;
function hasp_write;                stdcall; external;
function hasp_get_size;             stdcall; external;
function hasp_get_rtc;              stdcall; external;
function hasp_legacy_encrypt;       stdcall; external;
function hasp_legacy_decrypt;       stdcall; external;
function hasp_legacy_set_rtc;       stdcall; external;
function hasp_legacy_set_idletime;  stdcall; external;
function hasp_get_sessioninfo;      stdcall; external;
procedure hasp_free;                stdcall; external;
function hasp_update;               stdcall; external;
function hasp_datetime_to_hasptime; stdcall; external;
function hasp_hasptime_to_datetime; stdcall; external;
function hasp_login_scope;          stdcall; external;
function hasp_get_info;             stdcall; external;
function hasp_detach;               stdcall; external;
function hasp_transfer;             stdcall; external;
function hasp_get_version;          stdcall; external;
function hasp_cleanup;              stdcall; external;


{-----------------------------------------------------------------------------}

initialization

{-----------------------------------------------------------------------------}

finalization

{-----------------------------------------------------------------------------}

end.



