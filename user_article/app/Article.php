<?php

namespace App;
use App\Search\Searchable;
use Illuminate\Database\Eloquent\Model;

class Article extends Model
{
    //
    use Searchable;
    
    protected $guarded = ['created_at', 'updated_at'];

     protected $casts = [
        'author' => 'json',
        
    ];

    public function references()
    {
        return $this->hasMany('App\Reference');
    }
}
