//-----------------------------------------------------------------------------
#ifndef NetUnitH
#define NetUnitH
//-----------------------------------------------------------------------------
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <list>
//#include <string>
//-----------------------------------------------------------------------------
#define SERVER_NAME_LEN (255)
#define STG_HEADER     "NMS4"
#define OK_HEADER      "OKHD"
#define ERR_HEADER     "ERHD"
#define OK_LOGIN       "OKLG"
#define ERR_LOGIN      "ERLG"
#define OK_LOGINS      "OKLS"
#define ERR_LOGINS     "ERLS"
//-----------------------------------------------------------------------------
enum CONF_STATE {
 confHdr = 0,
 confLogin,
 confLoginCipher,
 confData
};
//-----------------------------------------------------------------------------
extern int                    nt_Transact(const char *);
extern void                   nt_SetIP(uint32_t i);
extern void                   nt_SetPort(uint16_t p);
extern void                   nt_SetLogin(const char * l);
extern void                   nt_SetPassword(const char * p);
extern int                    nt_Connect(void);
extern void                   nt_Disconnect(void);
//-----------------------------------------------------------------------------
#endif
//-----------------------------------------------------------------------------
