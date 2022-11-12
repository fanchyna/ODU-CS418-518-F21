<?php

namespace App\Http\Controllers;

use App\Article;
use App\Reference;
use Illuminate\Http\Request;
use App\Articles\ArticlesRepository;
use Illuminate\Support\Collection;
use Illuminate\Pagination\Paginator;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\DB;

class ArticlesController extends Controller
{
    //
    public function index()
    {
        $articles = \DB::table('articles')
                    ->join('references' ,'articles.id', '=', 'references.id')
                    ->select('*')
                    ->get();
        return view('articles.index', compact('articles'));
    }

    function search(ArticlesRepository $repository)
    {
        $results = $repository->search((string) request('q'));
        //$articlesArray = [];
        //if($results_count>0){
        //    foreach ($results['hits']['hits'] as $hit){
        //        $articlesArray[] = $hit['_source']['id'];
        //    }
        //}
        $articles = $this->paginate($results);

        return view('articles.index', [
            'articles' => $articles
        ]);
    }

     /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    public function paginate($items, $perPage = 5, $page = null, $options = [])
    {
        $page = $page ?: (Paginator::resolveCurrentPage() ?: 1);
        $items = $items instanceof Collection ? $items : Collection::make($items);
        return new LengthAwarePaginator($items->forPage($page, $perPage), $items->count(), $perPage, $page, $options);
    }
}
