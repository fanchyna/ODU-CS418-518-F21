<?php

namespace App;
use App\Search\Searchable;
use Illuminate\Database\Eloquent\Model;

class Reference extends Model
{
    //
    use Searchable;
    
    protected $guarded = ['created_at', 'updated_at'];
    public function articles()
    {
        return $this->belongsTo('App\Article');
    }
    
}

