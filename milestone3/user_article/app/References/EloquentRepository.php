<?php

namespace App\References;
use App\Reference;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;

class EloquentRepository implements ReferencesRepository
{
    public function search(string $query = ''): LengthAwarePaginator
    {
        return Reference::query()
            ->where('title', 'like', "%{$query}%")
            ->orWhere('time', 'like', "%{$query}%")
            ->orWhere('author', 'like', "%{$query}%")
            ->paginate();
    }
}
