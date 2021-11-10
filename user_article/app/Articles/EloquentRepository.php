<?php

namespace App\Articles;
use App\Article;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\DB;
class EloquentRepository implements ArticlesRepository
{
    public function search(string $query = ''): LengthAwarePaginator
    {
       $article = \DB::table('articles')
                ->join('references' ,'articles.id', '=', 'references.id')
                ->where('title', 'like', "%{$query}%")
                ->orWhere('time', 'like', "%{$query}%")
                ->orWhere('author', 'like', "%{$query}%")
                ->paginate();
        print_r($article);
        return $article;
    }
}
