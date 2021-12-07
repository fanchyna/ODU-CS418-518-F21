<?php

namespace App\Console\Commands;
use App\Article;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

class LoadArticlesData extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'articles:load';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'load article data from json file';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        //$json = json_decode(Storage::disk('local')::get('articles.json'), true);
        $path = storage_path( ) ."/articles.json";
        $file = trim(file_get_contents($path), "\xEF\xBB\xBF");
        $json = json_decode($file, true);
        $this->info('Loading articles from json. This might take a while...');
        
        foreach ($json as $item) {
            $this->info("\n write: ");
            $articleData = [
                'title' => $item['title'],
                'author' => $item['author'],
                'time' => $item['time'],
                'claim' => $item['claim'],
                'url' => $item['url']
            ];
            $this->info("\n read: ");
            $this->output->write('.');
            Article::create($articleData);
            $this->info("\n create: ");
            $this->output->write('.');
            $this->info("\n done: ");
        }
        
        $this->info("\n loading complete");
    }
}
