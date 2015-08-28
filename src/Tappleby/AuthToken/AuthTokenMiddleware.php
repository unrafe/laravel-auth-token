<?php
namespace Tappleby\AuthToken;

use Closure;
use Illuminate\Events\Dispatcher;
use App\AuthToken\Exceptions\NotAuthorizedException;
use Auth;

class AuthTokenMiddleware{

  /**
    * The event dispatcher instance.
    *
    * @var \Illuminate\Events\Dispatcher
    */
  protected $events;

  /**
  * @var \App\AuthToken\AuthTokenDriver
  */
  protected $driver;

  function __construct(AuthTokenDriver $driver, Dispatcher $events)
  {
    $this->driver = $driver;
    $this->events = $events;
  }


  /**
   * Handle an incoming request.
   *
   * @param  \Illuminate\Http\Request  $request
   * @param  \Closure  $next
   * @return mixed
   */
  public function handle($request, Closure $next)
  { 
    $payload = $request->header('X-Auth-Token');
    $user = $this->driver->validate($payload);
    if(!$user) {
      throw new NotAuthorizedException();
    }
    Auth::setUser($user);
    $this->events->fire('auth.token.valid', $user);
    return $next($request);
  }

}