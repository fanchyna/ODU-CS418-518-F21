<?php

namespace App\References;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;

interface ReferencesRepository {
    public function search (string $query = ''): Collection;
}
