<?php

namespace Keycloak;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;
use Keycloak\Auth\Guard\KeycloakWebGuard;
use Keycloak\Auth\KeycloakWebUserProvider;
use Keycloak\Middleware\KeycloakAuthenticated;
use Keycloak\Middleware\KeycloakCan;
use Keycloak\Models\KeycloakUser;
use Keycloak\Services\KeycloakService;
use Illuminate\Support\Facades\Route;

class KeycloakServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // User Provider
        Auth::provider('keycloak-users', function($app, array $config) {
            return new KeycloakWebUserProvider($config['model']);
        });
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        // Keycloak Web Guard
        Auth::extend('keycloak-web', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            return new KeycloakWebGuard($provider, $app->request);
        });

        // Facades
        $this->app->bind('keycloak-web', function($app) {
            return $app->make(KeycloakService::class);
        });

        // Routes
        $this->registerRoutes();

        // Middleware Group
        $this->app['router']->middlewareGroup('keycloak-web', [
            StartSession::class,
            KeycloakAuthenticated::class
        ]);

        $this->app['router']->aliasMiddleware('keycloak-web-can', KeycloakCan::class);

        // Interfaces
        $this->app->bind(ClientInterface::class, Client::class);
    }

    /**
     * Register the authentication routes for keycloak.
     *
     * @return void
     */
    private function registerRoutes()
    {
        $options = [
            'login' => env('ROUTE_PREFIX').'/login',
            'logout' => env('ROUTE_PREFIX').'/logout',
            //'register' => 'auth/register',
            'callback' => env('ROUTE_PREFIX').'/callback',
        ];
        // Register Routes
        $router = $this->app->make('router');

        Route::group(['middleware' => 'web','prefix'=>env('ROUTE_PREFIX')], function () use ($router, $options) {
    
            if (! empty($options['login'])) {
                $router->get($options['login'], 'Keycloak\Controllers\AuthController@login')->name('keycloak.login');
            }
    
            if (! empty($options['logout'])) {
                $router->get($options['logout'], 'Keycloak\Controllers\AuthController@logout')->name('keycloak.logout');
            }
    
            // if (! empty($options['register'])) {
            //     $router->get($options['register'], 'Keycloak\Controllers\AuthController@register')->name('keycloak.register');
            // }
    
            if (! empty($options['callback'])) {
                $router->get($options['callback'], 'Keycloak\Controllers\AuthController@callback')->name('keycloak.callback');
            }
        });
        
    }
}
