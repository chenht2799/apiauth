<?php
/**
* TOKEN令牌配置类
*/

namespace SdsAuth\src;

class TokenCfg
{
    //token版本号
    const VERSION = '1.0';

    //token过期时间，预留功能，目前先永不过期
    const EXPIRE_TIME = 30*24*3600;

    //加密类型动作参数
    const TOKEN_ENCODE   = 1;

    //解密类型动作参数
    const TOKEN_DECODE   = 2;

    //可逆加减密秘钥
    // const AUTH_KEY     = ')41OL*bM^*2P;!7Uj5H32Nfyz(4XmXh';  2019年10月25日过期更新
    const AUTH_KEY     = '5#wF&TpR*KvoV9z&1XP77vAxWC7CwSsn';

    //sign校验秘钥
    // const SIGN_KEY = ')YiwZtw~$9O)3i1)7Elj4n6NH;YD^e';  2019年10月25日过期更新
    const SIGN_KEY = '8v66HC&I4FE@s$Nf$diQXmG8#aFp515e';

    public function __construct() {}

}
