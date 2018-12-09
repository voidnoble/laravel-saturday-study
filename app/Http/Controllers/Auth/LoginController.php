<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    /**
     * Redirect the user to the Google authentication page.
     *
     * @return \Illuminate\Http\Response
     */
    public function redirectToProvider($provider)
    {
        return Socialite::driver($provider)->redirect();
    }

    /**
     * Obtain the user information from Google.
     *
     * @return \Illuminate\Http\Response
     */
    public function handleProviderCallback($provider)
    {
        try {
            $user = Socialite::driver($provider)->stateless()->user();
            $authUser = User::where('email', $user->email)->first();

            if ($authUser) {
                Auth::login($authUser, true);
                $user = $authUser;
            } else {
                $newUser = [
                    "name" => $user->name,
                    "email" => $user->email,
                    "provider" => $provider,
                    "provider_id" => $user->id,
                    "password" => $user->token,
                ];

                $addedUser = User::firstOrCreate($newUser);

                Auth::loginUsingId($addedUser->id);

                $user = $addedUser;
            }

            $data = $user->toArray();
            $data['provider'] = $provider;

            return redirect(route('home'))->with("data", $data);
        } catch (\Exception $e) {
            return redirect("/login")->with("error", $e->getMessage());
        }
    }
}
