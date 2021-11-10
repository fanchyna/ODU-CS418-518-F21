<?php

namespace App\Providers;
use App\Articles\ElasticsearchRepository;
use Elasticsearch\Client;
use App\Articles\ArticlesRepository;
use Elasticsearch\ClientBuilder;
use App\Articles\EloquentRepository;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
        $this->app->bind(ArticlesRepository::class, function($app) {
            // Use Eloquent if elasticsearch is switched off
             if (! config('services.search.enabled')) {
                 return new EloquentRepository();
             }
 
             return new ElasticsearchRepository (
                 $app->make(Client::class)
             );
           });
 
           $this->bindSearchClient();
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }

    private function bindSearchClient()
    {
        $this->app->bind(Client::class, function ($app) {
            return ClientBuilder::create()
                ->setHosts($app['config']->get('services.search.hosts'))
                ->build();
        });
    }
}
