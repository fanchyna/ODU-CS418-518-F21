<x-guest-layout>
    <x-jet-authentication-card>
        <x-slot name="logo">
            {{-- <x-jet-authentication-card-logo /> --}}
            <svg xmlns="http://www.w3.org/2000/svg" class="h-15 w-20 m-5" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd" />
            </svg>
        </x-slot>

        <div x-data="{ recovery: false }">
            <div class="mb-4 text-sm text-gray-600" x-show="! recovery">
                {{ __('Please confirm access to your account by entering the authentication code provided by your authenticator application.') }}
            </div>

            <div class="mb-4 text-sm text-gray-600" x-show="recovery">
                {{ __('Please confirm access to your account by entering one of your emergency recovery codes.') }}
            </div>

            <x-jet-validation-errors class="mb-4" />

            <form method="POST" action="{{ route('two-factor.login') }}">
                @csrf

                <div class="mt-4" x-show="! recovery">
                    <x-jet-label for="code" value="{{ __('Code') }}" />
                    <x-jet-input id="code" class="block mt-1 w-full" type="text" inputmode="numeric" name="code" autofocus x-ref="code" autocomplete="one-time-code" />
                </div>

                <div class="mt-4" x-show="recovery">
                    <x-jet-label for="recovery_code" value="{{ __('Recovery Code') }}" />
                    <x-jet-input id="recovery_code" class="block mt-1 w-full" type="text" name="recovery_code" x-ref="recovery_code" autocomplete="one-time-code" />
                </div>

                <div class="flex items-center justify-end mt-4">
                    <button type="button" class="text-sm text-gray-600 hover:text-gray-900 underline cursor-pointer"
                                    x-show="! recovery"
                                    x-on:click="
                                        recovery = true;
                                        $nextTick(() => { $refs.recovery_code.focus() })
                                    ">
                        {{ __('Use a recovery code') }}
                    </button>

                    <button type="button" class="text-sm text-gray-600 hover:text-gray-900 underline cursor-pointer"
                                    x-show="recovery"
                                    x-on:click="
                                        recovery = false;
                                        $nextTick(() => { $refs.code.focus() })
                                    ">
                        {{ __('Use an authentication code') }}
                    </button>

                    <x-jet-button class="ml-4">
                        {{ __('Log in') }}
                    </x-jet-button>
                </div>
            </form>
        </div>
    </x-jet-authentication-card>
</x-guest-layout>
