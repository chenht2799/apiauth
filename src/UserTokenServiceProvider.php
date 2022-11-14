<?php

namespace SdsAuth\src;

use Illuminate\Support\ServiceProvider;

class UserTokenServiceProvider extends ServiceProvider
{
    public function register()
    {
      
    }

    public function boot()
    {
        $this->publishes([
            __DIR__ . '/TokenCfg.php' => config_path('token_cfg.php'),
        ]);
    }
}
