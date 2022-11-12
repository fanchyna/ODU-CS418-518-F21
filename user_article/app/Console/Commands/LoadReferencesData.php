<?php


namespace App\Console\Commands;
require 'vendor/autoload.php';
use App\Reference;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;
use PhpScience\TextRank\Tool\StopWords\English;
use PhpScience\TextRank\TextRankFacade;
class LoadReferencesData extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'references:load';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'load reference data from json file';

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

        $path = storage_path( ) ."/references.json";
        $file = trim(file_get_contents($path), "\xEF\xBB\xBF");
        $json = json_decode($file, true);
        $this->info('Loading references from json. This might take a while...');
        
        foreach ($json as $item) {
            $this->info("\n write: ");
            $api = new TextRankFacade();
            // English implementation for stopwords/junk words:
            $stopWords = new English();
            $api->setStopWords($stopWords);
            $keycontent = implode(PHP_EOL,$api->summarizeTextBasic($item['content']));
            $referenceData = ['content'=>$item['content'], 'keycontent'=>$keycontent]; 
            Reference::create($referenceData);
            $this->output->write('.');
        }
        
        $this->info("\n loading complete");
    }
    
}
