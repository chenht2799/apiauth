# apiauth
移动端token auth
登录态TOKEN加减密


#安装部署
composer require chenht2799/apiauth

#laravel 适配安装
一、先在 config/app.php 添加 providers
```
SdsAuth\src\UserTokenServiceProvider::class
```

二、命令行执行语句生成配置文件
```
php artisan vendor:publish --provider="SdsAuth\src\UserTokenServiceProvider"
```
