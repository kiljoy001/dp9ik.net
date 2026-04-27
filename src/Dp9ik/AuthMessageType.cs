namespace Dp9ik;

public enum AuthMessageType : byte
{
    AuthTreq = 1,
    AuthChal = 2,
    AuthPass = 3,
    AuthOk = 4,
    AuthErr = 5,
    AuthMod = 6,
    AuthApop = 7,
    AuthOkVar = 9,
    AuthChap = 10,
    AuthMsChap = 11,
    AuthCram = 12,
    AuthHttp = 13,
    AuthVnc = 14,
    AuthPak = 19,
    AuthTs = 64,
    AuthTc = 65,
    AuthAs = 66,
    AuthAc = 67,
    AuthTp = 68,
    AuthHr = 69
}
