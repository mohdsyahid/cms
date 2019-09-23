Prerequisites
- Pengetahuan tentang PHP (version >= 7.1.3).
- Pengetahuan tentang Laravel (version 6).
- Install laragon (dah ada composer)


Kita akan create app Laravel yang mempunyai 3 class (admin,witer,user) dan jugak 'guard' untuk restricted part class ni. 

Create aplikasi laravel 

guna laragon > quick app > laravel. Tunggu sehingga siap. 

atau command installation laravel di terminal 


    $ composer create-project — prefer-dist laravel/laravel
    $ cd laravel
    
    

Buka file ( .env ) dalam folder projek yang kita buat tu . 

    DB_CONNECTION=mysql
    DB_HOST=127.0.0.1
    DB_PORT=3306
    DB_DATABASE=cms
    DB_USERNAME=root
    DB_PASSWORD=


Create migration untuk admin

    $ php artisan make:migration create_admins_table

Buka file dalam dir ini : 

    // database/migrations/<timestamp>_create_admins_table.php

    [...]
    public function up()
    {
        Schema::create('admins', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->boolean('is_super')->default(false);
            $table->rememberToken();
            $table->timestamps();
        });
    }
    [...]
lepastu buat data type untuk database admin ini , 

Create migration for writers :


    $ php artisan make:migration create_writers_table

Buka directory ni pastu edit macam yang kita nak , macam saya buat basic data type:

    database/migrations/<timestamp>_create_writers_table.php
    [...]
    public function up()
    {
        Schema::create('writers', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->boolean('is_editor')->default(false);
            $table->rememberToken();
            $table->timestamps();
        });
    }
    [...]
lepas dah siap create table / colum dalam file migration , kita run command untuk migrate table/column kita ke dalam database,
run commmand ini : 

    $ php artisan migrate
    
Ni untuk setup model class :- 


Admin model
run command ni :

    $ php artisan make:model Admin
Buka fail ni dalam dir yang diberi :

    // app/Admin.php
    <?php

    namespace App;

    use Illuminate\Notifications\Notifiable;
    use Illuminate\Foundation\Auth\User as Authenticatable;

    class Admin extends Authenticatable
    {
        use Notifiable;

        protected $guard = 'admin';

        protected $fillable = [
            'name', 'email', 'password',
        ];

        protected $hidden = [
            'password', 'remember_token',
        ];
    }


Writers model
To make the model for the writers, run the following command:

    $ php artisan make:model Writer
Buka fail ni dalam dir yang diberi :

    // app/Writer.php
    <?php

    namespace App;

    use Illuminate\Notifications\Notifiable;
    use Illuminate\Foundation\Auth\User as Authenticatable;

    class Writer extends Authenticatable
    {
        use Notifiable;

        protected $guard = 'writer';

        protected $fillable = [
            'name', 'email', 'password',
        ];

        protected $hidden = [
            'password', 'remember_token',
        ];
    }
Define the guards

buka config/auth.php dan letak guard baru mcm yang diberikan :

    // config/auth.php

    <?php

    [...]
    'guards' => [
        [...]
        'admin' => [
            'driver' => 'session',
            'provider' => 'admins',
        ],
        'writer' => [
            'driver' => 'session',
            'provider' => 'writers',
        ],
    ],
    [...]
    
   
 saya letak 2 guard admin dan writer pastu set provider sekali , provider ni untuk bagitau laravel auth apa yang kita gunakan untuk validation .

Passtu array guard :

    // config/auth.php

    [...]
    'providers' => [
        [...]
        'admins' => [
            'driver' => 'eloquent',
            'model' => App\Admin::class,
        ],
        'writers' => [
            'driver' => 'eloquent',
            'model' => App\Writer::class,
        ],
    ],
    [...]


Ubah  LoginController

Bukan LoginController fail dalam directory app/Http/Controllers/Auth pastu edit macam yang diberikan :

    // app/Http/Controllers/Auth/LoginController.php

    <?php

    namespace App\Http\Controllers\Auth;

    use App\Http\Controllers\Controller;
    use Illuminate\Foundation\Auth\AuthenticatesUsers;
    [...]
    use Illuminate\Http\Request;
    use Auth;
    [...]
    class LoginController extends Controller
    {
        [...]
        public function __construct()
        {
            $this->middleware('guest')->except('logout');
            $this->middleware('guest:admin')->except('logout');
            $this->middleware('guest:writer')->except('logout');
        }
        [...]
    }


Pastu , define the login for admins:

    // app/Http/Controllers/Auth/LoginController.php

    [...]
    public function showAdminLoginForm()
    {
        return view('auth.login', ['url' => 'admin']);
    }

    public function adminLogin(Request $request)
    {
        $this->validate($request, [
            'email'   => 'required|email',
            'password' => 'required|min:6'
        ]);

        if (Auth::guard('admin')->attempt(['email' => $request->email, 'password' => $request->password], $request->get('remember'))) {

            return redirect()->intended('/admin');
        }
        return back()->withInput($request->only('email', 'remember'));
    }
    [...]

Buat perkara yang sama jugak dekat writer : 

    // app/Http/Controllers/Auth/LoginController.php


    [...]
    public function showWriterLoginForm()
    {
        return view('auth.login', ['url' => 'writer']);
    }

    public function writerLogin(Request $request)
    {
        $this->validate($request, [
            'email'   => 'required|email',
            'password' => 'required|min:6'
        ]);

        if (Auth::guard('writer')->attempt(['email' => $request->email, 'password' => $request->password], $request->get('remember'))) {

            return redirect()->intended('/writer');
        }
        return back()->withInput($request->only('email', 'remember'));
    }
    [...]
And our login is set. Hurray!

Ubah RegisterController
Buka  RegisterController pastu ikut macam yg diberi:

    // app/Http/Controllers/Auth/RegisterController.php

    <?php
    [...]
    namespace App\Http\Controllers\Auth;
    use App\User;
    use App\Admin;
    use App\Writer;
    use App\Http\Controllers\Controller;
    use Illuminate\Support\Facades\Hash;
    use Illuminate\Support\Facades\Validator;
    use Illuminate\Foundation\Auth\RegistersUsers;
    use Illuminate\Http\Request;
    [...]
    class RegisterController extends Controller
    {
        [...]
        public function __construct()
        {
            $this->middleware('guest');
            $this->middleware('guest:admin');
            $this->middleware('guest:writer');
        }
      [...]
    }


Pastu , kita setup method untuk kembali registarion page ke different user : 

    // app/Http/Controllers/Auth/RegisterController.php

    [...]
    public function showAdminRegisterForm()
    {
        return view('auth.register', ['url' => 'admin']);
    }

    public function showWriterRegisterForm()
    {
        return view('auth.register', ['url' => 'writer']);
    }
    [...]

Controller untuk  admin:

    // app/Http/Controllers/Auth/RegisterController.php

    [...] 
    protected function createAdmin(Request $request)
    {
        $this->validator($request->all())->validate();
        $admin = Admin::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => Hash::make($request['password']),
        ]);
        return redirect()->intended('login/admin');
    }
    [...] 
method untuk  writer:

    // app/Http/Controllers/Auth/RegisterController.php

    [...] 
    protected function createWriter(Request $request)
    {
        $this->validator($request->all())->validate();
        $writer = Writer::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => Hash::make($request['password']),
        ]);
        return redirect()->intended('login/writer');
    }
    [...] 

Untuk pendaftaran dah complete. 

Set up authentication pages
Untuk setup ath kat laravel 6 ni ada 3 step 
1. composer require laravel/ui
2. php artisan ui vue --auth
3. npm install && npm run dev

    $ php artisan make:auth



Open the login.blade.php file and edit as follows:

    // resources/views/auth/login.blade.php
    [...]
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header"> {{ isset($url) ? ucwords($url) : ""}} {{ __('Login') }}</div>

                    <div class="card-body">
                        @isset($url)
                        <form method="POST" action='{{ url("login/$url") }}' aria-label="{{ __('Login') }}">
                        @else
                        <form method="POST" action="{{ route('login') }}" aria-label="{{ __('Login') }}">
                        @endisset
                            @csrf
        [...]
    </div>


Open the register.blade.php file and edit as follows:

    // resources/views/auth/register.blade.php

    [...]
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header"> {{ isset($url) ? ucwords($url) : ""}} {{ __('Register') }}</div>

                    <div class="card-body">
                        @isset($url)
                        <form method="POST" action='{{ url("register/$url") }}' aria-label="{{ __('Register') }}">
                        @else
                        <form method="POST" action="{{ route('register') }}" aria-label="{{ __('Register') }}">
                        @endisset
                            @csrf
        [...]
    </div>
lepas dah siap yang atas create file ni dalam folder projek . 
   - resources/views/layouts/auth.blade.php
   - resources/views/admin.blade.php
    - resources/views/writer.blade.php
  - resources/views/home.blade.php
Insert this code block into the auth.blade.php file:

    // resources/views/layouts/auth.blade.php

    <!DOCTYPE html>
    <html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <!-- CSRF Token -->
        <meta name="csrf-token" content="{{ csrf_token() }}">

        <title>{{ config('app.name', 'Laravel') }}</title>

        <!-- Scripts -->
        <script src="{{ asset('js/app.js') }}" defer></script>

        <!-- Fonts -->
        <link rel="dns-prefetch" href="https://fonts.gstatic.com">
        <link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css">

        <!-- Styles -->
        <link href="{{ asset('css/app.css') }}" rel="stylesheet">
    </head>
    <body>
        <div id="app">
            <nav class="navbar navbar-expand-md navbar-light navbar-laravel">
                <div class="container">
                    <a class="navbar-brand" href="{{ url('/') }}">
                        {{ config('app.name', 'Laravel') }}
                    </a>
                    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="{{ __('Toggle navigation') }}">
                        <span class="navbar-toggler-icon"></span>
                    </button>

                    <div class="collapse navbar-collapse" id="navbarSupportedContent">
                        <!-- Left Side Of Navbar -->
                        <ul class="navbar-nav mr-auto">

                        </ul>

                        <!-- Right Side Of Navbar -->
                        <ul class="navbar-nav ml-auto">
                            <!-- Authentication Links -->
                           <li class="nav-item dropdown">
                                <a id="navbarDropdown" class="nav-link dropdown-toggle" href="#" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" v-pre>
                                    Hi There <span class="caret"></span>
                                </a>

                                <div class="dropdown-menu dropdown-menu-right" aria-labelledby="navbarDropdown">
                                    <a class="dropdown-item" href="{{ route('logout') }}"
                                       onclick="event.preventDefault();
                                                     document.getElementById('logout-form').submit();">
                                        {{ __('Logout') }}
                                    </a>

                                    <form id="logout-form" action="{{ route('logout') }}" method="POST" style="display: none;">
                                        @csrf
                                    </form>
                                </div>
                            </li>
                        </ul>
                    </div>
                </div>
            </nav>

            <main class="py-4">
                @yield('content')
            </main>
        </div>
    </body>
    </html>
Next, insert this code block into the admin.blade.php file:

    // resources/views/admin.blade.php

    @extends('layouts.auth')

    @section('content')
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">Dashboard</div>

                    <div class="card-body">
                        Hi boss!
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endsection
Open the writer.blade.php file and edit as follows:

    // resources/views/writer.blade.php

    @extends('layouts.auth')

    @section('content')
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">Dashboard</div>

                    <div class="card-body">
                        Hi there, awesome writer
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endsection
Finally, open the home.blade.php file and replace dengan yang ni :

    // resources/views/home.blade.php

    @extends('layouts.auth')

    @section('content')
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">Dashboard</div>

                    <div class="card-body">
                         Hi there, regular user
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endsection
Set up the routes
pastu ikut code yang diberikan 

    // routes/web.php


    <?php
    Route::view('/', 'welcome');
    Auth::routes();

    Route::get('/login/admin', 'Auth\LoginController@showAdminLoginForm');
    Route::get('/login/writer', 'Auth\LoginController@showWriterLoginForm');
    Route::get('/register/admin', 'Auth\RegisterController@showAdminRegisterForm');
    Route::get('/register/writer', 'Auth\RegisterController@showWriterRegisterForm');

    Route::post('/login/admin', 'Auth\LoginController@adminLogin');
    Route::post('/login/writer', 'Auth\LoginController@writerLogin');
    Route::post('/register/admin', 'Auth\RegisterController@createAdmin');
    Route::post('/register/writer', 'Auth\RegisterController@createWriter');

    Route::view('/home', 'home')->middleware('auth');
    Route::view('/admin', 'admin');
    Route::view('/writer', 'writer');
Modify how our users are redirected if authenticated
It is important you modify how users are redirected when they are authenticated. Laravel by default redirects all authenticated users to /home. We will get the error below if we do not modify the redirection.



So, to solve that, open the app/Http/Controllers/Middleware/RedirectIfAuthenticated.php file and replace with this:

    // app/Http/Controllers/Middleware/RedirectIfAuthenticated.php

    <?php

    namespace App\Http\Middleware;

    use Closure;
    use Illuminate\Support\Facades\Auth;

    class RedirectIfAuthenticated
    {
        public function handle($request, Closure $next, $guard = null)
        {
            if ($guard == "admin" && Auth::guard($guard)->check()) {
                return redirect('/admin');
            }
            if ($guard == "writer" && Auth::guard($guard)->check()) {
                return redirect('/writer');
            }
            if (Auth::guard($guard)->check()) {
                return redirect('/home');
            }

            return $next($request);
        }
    }
The RedirectIfAuthenticated middleware receives the auth guard as a parameter. This middleware is triggered when we try to visit any page meant for authenticated users. We can then determine the type of authentication the user has and redirect them accordingly.

Modify authentication exception handler
There is a little annoying thing that would happen when a user is redirected. You would expect that if a user tries to access say /writer but is not authenticated, that the user is redirected to /login/writer, yes? Well, they don’t. They get redirected to /login which is not what we want.

To ensure that when a user tries to visit /writer they are redirected to /login/writer or the same for /admin, we have to modify the exception handler. Open the handler file in app/Exceptions and add the following:

    // app/Exceptions/Handler.php

    <?php

    namespace App\Exceptions;

    use Exception;
    use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
    [...]
    use Illuminate\Auth\AuthenticationException;
    use Auth; 
    [...]
    class Handler extends ExceptionHandler
    {
       [...] 
        protected function unauthenticated($request, AuthenticationException $exception)
        {
            if ($request->expectsJson()) {
                return response()->json(['error' => 'Unauthenticated.'], 401);
            }
            if ($request->is('admin') || $request->is('admin/*')) {
                return redirect()->guest('/login/admin');
            }
            if ($request->is('writer') || $request->is('writer/*')) {
                return redirect()->guest('/login/writer');
            }
            return redirect()->guest(route('login'));
        }
    }
The unauthenticated method we just added resolves this issue we have. It receives an AuthenticationExpection exception by default which carries that guard information. Sadly, we cannot access that, because it is protected (hopefully, Laravel 5.7 will come with a way to access it).

Our workaround is to use request→is(). This checks the URL we are trying to access. It can also check the URL pattern if we do not have an absolute URL or if we have a route group.

In our case, we first check if we received a JSON request and handle the exception separately. Then we check if we are trying to access /admin or any URL preceded by admin. We redirect the user to the appropriate login page. We also do the check for writer as well.

This is a good workaround for us, but it means we must know the absolute URL we want to access, or at least have the same prefix for all routes that will be protected by our guard.

Run the application
Now that our application is ready, run the following command to get it up:

    $ php artisan serve
It should typically be available on http://localhost atau pun projek.test. 

Remember to visit http://localhost/register/writer and http://localhost/register/admin to register writers and admins respectively. Then visit http://localhost/login/writer and http://localhost/login/admin to login the writers and admins respectively.






































<p align="center"><img src="https://res.cloudinary.com/dtfbvvkyp/image/upload/v1566331377/laravel-logolockup-cmyk-red.svg" width="400"></p>

<p align="center">
<a href="https://travis-ci.org/laravel/framework"><img src="https://travis-ci.org/laravel/framework.svg" alt="Build Status"></a>
<a href="https://packagist.org/packages/laravel/framework"><img src="https://poser.pugx.org/laravel/framework/d/total.svg" alt="Total Downloads"></a>
<a href="https://packagist.org/packages/laravel/framework"><img src="https://poser.pugx.org/laravel/framework/v/stable.svg" alt="Latest Stable Version"></a>
<a href="https://packagist.org/packages/laravel/framework"><img src="https://poser.pugx.org/laravel/framework/license.svg" alt="License"></a>
</p>

## About Laravel

Laravel is a web application framework with expressive, elegant syntax. We believe development must be an enjoyable and creative experience to be truly fulfilling. Laravel takes the pain out of development by easing common tasks used in many web projects, such as:

- [Simple, fast routing engine](https://laravel.com/docs/routing).
- [Powerful dependency injection container](https://laravel.com/docs/container).
- Multiple back-ends for [session](https://laravel.com/docs/session) and [cache](https://laravel.com/docs/cache) storage.
- Expressive, intuitive [database ORM](https://laravel.com/docs/eloquent).
- Database agnostic [schema migrations](https://laravel.com/docs/migrations).
- [Robust background job processing](https://laravel.com/docs/queues).
- [Real-time event broadcasting](https://laravel.com/docs/broadcasting).

Laravel is accessible, powerful, and provides tools required for large, robust applications.

## Learning Laravel

Laravel has the most extensive and thorough [documentation](https://laravel.com/docs) and video tutorial library of all modern web application frameworks, making it a breeze to get started with the framework.

If you don't feel like reading, [Laracasts](https://laracasts.com) can help. Laracasts contains over 1500 video tutorials on a range of topics including Laravel, modern PHP, unit testing, and JavaScript. Boost your skills by digging into our comprehensive video library.

## Laravel Sponsors

We would like to extend our thanks to the following sponsors for funding Laravel development. If you are interested in becoming a sponsor, please visit the Laravel [Patreon page](https://patreon.com/taylorotwell).

- **[Vehikl](https://vehikl.com/)**
- **[Tighten Co.](https://tighten.co)**
- **[Kirschbaum Development Group](https://kirschbaumdevelopment.com)**
- **[64 Robots](https://64robots.com)**
- **[Cubet Techno Labs](https://cubettech.com)**
- **[Cyber-Duck](https://cyber-duck.co.uk)**
- **[British Software Development](https://www.britishsoftware.co)**
- **[Webdock, Fast VPS Hosting](https://www.webdock.io/en)**
- **[DevSquad](https://devsquad.com)**
- [UserInsights](https://userinsights.com)
- [Fragrantica](https://www.fragrantica.com)
- [SOFTonSOFA](https://softonsofa.com/)
- [User10](https://user10.com)
- [Soumettre.fr](https://soumettre.fr/)
- [CodeBrisk](https://codebrisk.com)
- [1Forge](https://1forge.com)
- [TECPRESSO](https://tecpresso.co.jp/)
- [Runtime Converter](http://runtimeconverter.com/)
- [WebL'Agence](https://weblagence.com/)
- [Invoice Ninja](https://www.invoiceninja.com)
- [iMi digital](https://www.imi-digital.de/)
- [Earthlink](https://www.earthlink.ro/)
- [Steadfast Collective](https://steadfastcollective.com/)
- [We Are The Robots Inc.](https://watr.mx/)
- [Understand.io](https://www.understand.io/)
- [Abdel Elrafa](https://abdelelrafa.com)
- [Hyper Host](https://hyper.host)

## Contributing

Thank you for considering contributing to the Laravel framework! The contribution guide can be found in the [Laravel documentation](https://laravel.com/docs/contributions).

## Security Vulnerabilities

If you discover a security vulnerability within Laravel, please send an e-mail to Taylor Otwell via [taylor@laravel.com](mailto:taylor@laravel.com). All security vulnerabilities will be promptly addressed.

## License

The Laravel framework is open-source software licensed under the [MIT license](https://opensource.org/licenses/MIT).
