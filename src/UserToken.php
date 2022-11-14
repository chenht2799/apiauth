<?php
/**
* TOKEN令牌
*/

namespace SdsAuth\src;

use SdsAuth\src\TokenCfg;

class UserToken
{
    
    /**
     * 生成app token令牌
     * @param  [type] $mid [description]
     * @return [type]      [description]
     */
    public static function createAppToken($mid, $clientId)
    {
        if (empty($mid) || empty($clientId)) {
            return false;
        }

        $data = [
            'mid'         => $mid,
            'login_time'  => time(),
            'expire_time' => TokenCfg::EXPIRE_TIME,
            'random'      => rand(1, 1000),
            'version'     => TokenCfg::VERSION,
            'client_id'   => $clientId,
        ];
        $data['sign'] = self::_makeSign($data);

        $data = implode('|', $data);

        $authData = urlencode(base64_encode(self::_authcode($data, TokenCfg::TOKEN_ENCODE, TokenCfg::AUTH_KEY)));

        return $authData;
    }


    /**
     * app客户端Token校验
     * @param  [type] $token    [description]
     * @param  [type] $clientId [description]
     * @return [type]           [description]
     */
    public static function verifyAppToken($token, $clientId)
    {
        if (empty($token) || empty($clientId)) {
            return 0;
        }

        $data = self::parseToken($token);

        if (empty($data)) {
            return 0;
        }

        //校验token里面的sign数据
        if (! self::_vierfySign($data)) {
            return 0;
        }

        //校验token的client_id是否与客户端传上来的一致
        if ($data['client_id'] !== $clientId) {
            return 0;
        }

        return $data['mid'];
    }


    /**
     * 解析token令牌
     * @return [type] [description]
     */
    public static function parseToken($token)
    {
        if ($token === '') {
            return false;
        }

        //解码
        $tokenStr = self::_authcode(base64_decode(urldecode($token)), TokenCfg::TOKEN_DECODE, TokenCfg::AUTH_KEY);

        if (empty($tokenStr)) {
            return false;
        }

        @list($mid, $loginTime, $expireTime, $random, $version, $clientId, $sign) = explode('|', $tokenStr);

        $data = [
            'mid'         => (int)$mid,
            'login_time'  => (int)$loginTime,
            'expire_time' => (int)$expireTime,
            'random'      => (int)$random,
            'version'     => $version,
            'client_id'   => $clientId,
            'sign'        => $sign,
        ];

        return $data;
    }

    /**
     * 生成sign校验码
     * @param  [type] $data [description]
     * @return [type]       [description]
     */
    private static function _makeSign($data)
    {
        unset($data['sign']);

        return md5(self::_makeSource($data));
    }


    /**
     * 构造sign加密数据源
     * @param  [type] $data [description]
     * @return [type]       [description]
     */
    private static function _makeSource($data)
    {
        $str = '';
        ksort($data);

        foreach ($data as $k => $v) {
            $str .= "{$k}={$v}&";
        }

        return $str.'key='.TokenCfg::SIGN_KEY;
    }


    /**
     * 校验sign校验码
     * @param  [type] $data [description]
     * @return [type]       [description]
     */
    private static function _vierfySign($data)
    {
        if (empty($data)) {
            return false;
        }

        $sign = $data['sign'];

        $mySign = self::_makeSign($data);

        if ($sign != $mySign) {
            return false;
        }

        return true;
    }


    /**
     * [authcode 加解密]
     * @Author   Jason
     * @DateTime 2018-01-10T14:52:10+0800
     * @param    [type]                   $string     [加密数据]
     * @param    [type]                   $operation  [1加密，2解密]
     * @param    integer                  $expireTime [过期时间]
     * @param    [type]                   $key        [加密key]
     * @return   [type]                               [description]
     */
    private static function _authcode($string, $operation = 1, $key = '', $expireTime = 0)
    {
        // 动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙
        $ckey_length = 4;
        
        // 密匙a会参与加解密
        $keya = md5(substr($key, 0, 16));
        // 密匙b会用来做数据完整性验证
        $keyb = md5(substr($key, 16, 16));
        // 密匙c用于变化生成的密文
        $keyc = $ckey_length ? ($operation == 2 ? substr($string, 0, $ckey_length) : substr(md5(microtime()), - $ckey_length)) : '';
        // 参与运算的密匙
        $cryptkey = $keya . md5($keya . $keyc);
        $key_length = strlen($cryptkey);
        // 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$keyb(密匙b)，
        // 解密时会通过这个密匙验证数据完整性
        // 如果是解码的话，会从第$ckey_length位开始，因为密文前$ckey_length位保存 动态密匙，以保证解密正确
        $string = $operation == 2 ? self::_base64urlDecode(substr($string, $ckey_length)) : sprintf('%010d', $expireTime ? $expireTime + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        $string_length = strlen($string);
        $result = '';
        $box = range(0, 255);
        $rndkey = array();
        // 产生密匙簿
        for ($i = 0; $i <= 255; $i ++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        // 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上对并不会增加密文的强度
        for ($j = $i = 0; $i < 256; $i ++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        // 核心加解密部分
        for ($a = $j = $i = 0; $i < $string_length; $i ++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            // 从密匙簿得出密匙进行异或，再转成字符
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        if ($operation == 2) {
            // 验证数据有效性，请看未加密明文的格式
             if ((substr($result, 0, 10) == 0 || intval(substr($result, 0, 10)) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
                return substr($result, 26);
            } else {
                return '';
            }
        } else {
            // 把动态密匙保存在密文里，这也是为什么同样的明文，生产不同密文后能解密的原因
            // 因为加密后的密文可能是一些特殊字符，复制过程可能会丢失，所以用base64编码
            return $keyc . str_replace('=', '', self::_base64urlEncode($result));
        }
    }


    /**
     * [base64url_encode url参数的base64加密]
     * @Author   Jason
     * @DateTime 2016-05-17T18:49:12+0800
     * @param    [type]                   $data [description]
     * @return   [type]                         [description]
     */
    private static function _base64urlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * [base64url_decode url参数的base64解密]
     * @Author   Jason
     * @DateTime 2016-05-17T18:49:36+0800
     * @param    [type]                   $data [description]
     * @return   [type]                         [description]
     */
    private static function _base64urlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
