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
            KeycloakAuthenticated::class,
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
        $defaults = [
            'login' => 'login',
            'logout' => 'logout',
            'register' => 'register',
            'callback' => 'callback',
        ];

        $options = Config::get('keycloak-web.routes', []);
        $options = array_merge($defaults, $options);

        // Register Routes
        $router = $this->app->make('router');

        $middlewares = [
            \App\Http\Middleware\EncryptCookies::class,
            \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
            \Illuminate\Session\Middleware\StartSession::class,
        ];

        if (! empty($options['login'])) {
            $router->middleware($middlewares)->get($options['login'], 'Keycloak\Controllers\AuthController@login')->name('keycloak.login');
        }

        if (! empty($options['logout'])) {
            $router->middleware($middlewares)->get($options['logout'], 'Keycloak\Controllers\AuthController@logout')->name('keycloak.logout');
        }

        if (! empty($options['register'])) {
            $router->middleware($middlewares)->get($options['register'], 'Keycloak\Controllers\AuthController@register')->name('keycloak.register');
        }

        if (! empty($options['callback'])) {
            $router->middleware($middlewares)->get($options['callback'], 'Keycloak\Controllers\AuthController@callback')->name('keycloak.callback');
        }
    }
}
