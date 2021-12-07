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
        return view('articles.index', ['articles' => $articles]);
    }

    function search(ArticlesRepository $repository)
    {
        //$results = $repository->search((string) request('q'));
        //$articlesArray = [];
        //if($results_count>0){
        //    foreach ($results['hits']['hits'] as $hit){
        //        $articlesArray[] = $hit['_source']['id'];
        //    }
        //}
        //$articles = $this->paginate($results);

        //return view('articles.index', [
        //    'articles' => $articles
        //]);

        if(true) {

            // Search for given text and return data
            
            $data = $repository->searchOnElasticsearch(request('q'));
            
            $articlesArray = [];

            // If there are any articles that match given search text "hits" fill their id's in array
            if($data['hits']['total'] > 0) {

                foreach ($data['hits']['hits'] as $hit) {
                    $articlesArray[] = $hit['_source']['id'];
                }
            }
            
            // Retrieve found articles from database
            $articles = \DB::table('articles')
                        ->join('references' ,'articles.id', '=', 'references.id')
                        ->whereIn("references.id",$articlesArray)
                        ->select('*')
                        ->get();

            // Return to view with data
            
            return view('articles.index', ['articles' => $articles]);
        } else {
            return redirect()->route('articles');
        }
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

    public function show(Article $article)
    {
        return $article;
    }

    public function store(Request $request)
    {
        $article = Article::create($request->all());

        return response()->json($article, 201);
    }

    public function update(Request $request, Article $article)
    {
        $article->update($request->all());

        return response()->json($article, 200);
    }

    public function delete(Article $article)
    {
        $article->delete();

        return response()->json(null, 204);
    }
}
