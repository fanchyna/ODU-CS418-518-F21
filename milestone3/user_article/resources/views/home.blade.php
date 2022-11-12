@extends('layouts.app')

@section('content')
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">{{ __('Dashboard') }}</div>

                <div class="card-body">
                    @if (session('status'))
                        <div class="alert alert-success" role="alert">
                            {{ session('status') }}
                        </div>
                    @endif

                    {{ __('You are logged in!') }}

                    <form action="{{ url('search') }}" method="get" autocomplete="off">
                        <label>
                            Search for Something
                            <input type="text" name="q" class="border p-2 w-full" placeholder="Search..." spellcheck="true"
                            value="{{ request('q') }}" />
                            
                        </label>
                        
                        
                    </form>
                    
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
