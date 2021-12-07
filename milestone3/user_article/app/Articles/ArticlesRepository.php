<?php

namespace App\Articles;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;

interface ArticlesRepository {
    public function search (string $query = ''): Collection;
}
