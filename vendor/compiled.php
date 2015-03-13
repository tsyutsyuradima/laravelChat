<?php
namespace Illuminate\Contracts\Container;

use Closure;
interface Container
{
    public function bound($abstract);
    public function alias($abstract, $alias);
    public function tag($abstracts, $tags);
    public function tagged($tag);
    public function bind($abstract, $concrete = null, $shared = false);
    public function bindIf($abstract, $concrete = null, $shared = false);
    public function singleton($abstract, $concrete = null);
    public function extend($abstract, Closure $closure);
    public function instance($abstract, $instance);
    public function when($concrete);
    public function make($abstract, $parameters = array());
    public function call($callback, array $parameters = array(), $defaultMethod = null);
    public function resolved($abstract);
    public function resolving($abstract, Closure $callback = null);
    public function afterResolving($abstract, Closure $callback = null);
}
namespace Illuminate\Contracts\Container;

interface ContextualBindingBuilder
{
    public function needs($abstract);
    public function give($implementation);
}
namespace Illuminate\Contracts\Foundation;

use Illuminate\Contracts\Container\Container;
interface Application extends Container
{
    public function version();
    public function basePath();
    public function environment();
    public function isDownForMaintenance();
    public function registerConfiguredProviders();
    public function register($provider, $options = array(), $force = false);
    public function registerDeferredProvider($provider, $service = null);
    public function boot();
    public function booting($callback);
    public function booted($callback);
}
namespace Illuminate\Contracts\Bus;

use Closure;
use ArrayAccess;
interface Dispatcher
{
    public function dispatchFromArray($command, array $array);
    public function dispatchFrom($command, ArrayAccess $source, array $extras = array());
    public function dispatch($command, Closure $afterResolving = null);
    public function dispatchNow($command, Closure $afterResolving = null);
    public function pipeThrough(array $pipes);
}
namespace Illuminate\Contracts\Bus;

interface QueueingDispatcher extends Dispatcher
{
    public function dispatchToQueue($command);
}
namespace Illuminate\Contracts\Bus;

use Closure;
interface HandlerResolver
{
    public function resolveHandler($command);
    public function getHandlerClass($command);
    public function getHandlerMethod($command);
    public function maps(array $commands);
    public function mapUsing(Closure $mapper);
}
namespace Illuminate\Contracts\Pipeline;

use Closure;
interface Pipeline
{
    public function send($traveler);
    public function through($stops);
    public function via($method);
    public function then(Closure $destination);
}
namespace Illuminate\Contracts\Support;

interface Renderable
{
    public function render();
}
namespace Illuminate\Contracts\Logging;

interface Log
{
    public function alert($message, array $context = array());
    public function critical($message, array $context = array());
    public function error($message, array $context = array());
    public function warning($message, array $context = array());
    public function notice($message, array $context = array());
    public function info($message, array $context = array());
    public function debug($message, array $context = array());
    public function log($level, $message, array $context = array());
    public function useFiles($path, $level = 'debug');
    public function useDailyFiles($path, $days = 0, $level = 'debug');
}
namespace Illuminate\Contracts\Config;

interface Repository
{
    public function has($key);
    public function get($key, $default = null);
    public function set($key, $value = null);
    public function prepend($key, $value);
    public function push($key, $value);
}
namespace Illuminate\Contracts\Events;

interface Dispatcher
{
    public function listen($events, $listener, $priority = 0);
    public function hasListeners($eventName);
    public function until($event, $payload = array());
    public function fire($event, $payload = array(), $halt = false);
    public function firing();
    public function forget($event);
    public function forgetPushed();
}
namespace Illuminate\Contracts\Support;

interface Arrayable
{
    public function toArray();
}
namespace Illuminate\Contracts\Support;

interface Jsonable
{
    public function toJson($options = 0);
}
namespace Illuminate\Contracts\Cookie;

interface Factory
{
    public function make($name, $value, $minutes = 0, $path = null, $domain = null, $secure = false, $httpOnly = true);
    public function forever($name, $value, $path = null, $domain = null, $secure = false, $httpOnly = true);
    public function forget($name, $path = null, $domain = null);
}
namespace Illuminate\Contracts\Cookie;

interface QueueingFactory extends Factory
{
    public function queue();
    public function unqueue($name);
    public function getQueuedCookies();
}
namespace Illuminate\Contracts\Encryption;

interface Encrypter
{
    public function encrypt($value);
    public function decrypt($payload);
    public function setMode($mode);
    public function setCipher($cipher);
}
namespace Illuminate\Contracts\Queue;

interface QueueableEntity
{
    public function getQueueableId();
}
namespace Illuminate\Contracts\Routing;

use Closure;
interface Registrar
{
    public function get($uri, $action);
    public function post($uri, $action);
    public function put($uri, $action);
    public function delete($uri, $action);
    public function patch($uri, $action);
    public function options($uri, $action);
    public function match($methods, $uri, $action);
    public function resource($name, $controller, array $options = array());
    public function group(array $attributes, Closure $callback);
    public function before($callback);
    public function after($callback);
    public function filter($name, $callback);
}
namespace Illuminate\Contracts\Routing;

interface ResponseFactory
{
    public function make($content = '', $status = 200, array $headers = array());
    public function view($view, $data = array(), $status = 200, array $headers = array());
    public function json($data = array(), $status = 200, array $headers = array(), $options = 0);
    public function jsonp($callback, $data = array(), $status = 200, array $headers = array(), $options = 0);
    public function stream($callback, $status = 200, array $headers = array());
    public function download($file, $name = null, array $headers = array(), $disposition = 'attachment');
    public function redirectTo($path, $status = 302, $headers = array(), $secure = null);
    public function redirectToRoute($route, $parameters = array(), $status = 302, $headers = array());
    public function redirectToAction($action, $parameters = array(), $status = 302, $headers = array());
    public function redirectGuest($path, $status = 302, $headers = array(), $secure = null);
    public function redirectToIntended($default = '/', $status = 302, $headers = array(), $secure = null);
}
namespace Illuminate\Contracts\Routing;

interface UrlGenerator
{
    public function to($path, $extra = array(), $secure = null);
    public function secure($path, $parameters = array());
    public function asset($path, $secure = null);
    public function route($name, $parameters = array(), $absolute = true);
    public function action($action, $parameters = array(), $absolute = true);
    public function setRootControllerNamespace($rootNamespace);
}
namespace Illuminate\Contracts\Routing;

interface UrlRoutable
{
    public function getRouteKey();
    public function getRouteKeyName();
}
namespace Illuminate\Contracts\Routing;

use Closure;
interface Middleware
{
    public function handle($request, Closure $next);
}
namespace Illuminate\Contracts\Routing;

interface TerminableMiddleware extends Middleware
{
    public function terminate($request, $response);
}
namespace Illuminate\Contracts\Validation;

interface ValidatesWhenResolved
{
    public function validate();
}
namespace Illuminate\Contracts\View;

interface Factory
{
    public function exists($view);
    public function file($path, $data = array(), $mergeData = array());
    public function make($view, $data = array(), $mergeData = array());
    public function share($key, $value = null);
    public function composer($views, $callback, $priority = null);
    public function creator($views, $callback);
    public function addNamespace($namespace, $hints);
}
namespace Illuminate\Contracts\Support;

interface MessageProvider
{
    public function getMessageBag();
}
namespace Illuminate\Contracts\Support;

interface MessageBag
{
    public function keys();
    public function add($key, $message);
    public function merge($messages);
    public function has($key = null);
    public function first($key = null, $format = null);
    public function get($key, $format = null);
    public function all($format = null);
    public function getFormat();
    public function setFormat($format = ':message');
    public function isEmpty();
    public function count();
    public function toArray();
}
namespace Illuminate\Contracts\View;

use Illuminate\Contracts\Support\Renderable;
interface View extends Renderable
{
    public function name();
    public function with($key, $value = null);
}
namespace Illuminate\Contracts\Http;

interface Kernel
{
    public function bootstrap();
    public function handle($request);
    public function terminate($request, $response);
    public function getApplication();
}
namespace Illuminate\Contracts\Auth;

interface Guard
{
    public function check();
    public function guest();
    public function user();
    public function once(array $credentials = array());
    public function attempt(array $credentials = array(), $remember = false, $login = true);
    public function basic($field = 'email');
    public function onceBasic($field = 'email');
    public function validate(array $credentials = array());
    public function login(Authenticatable $user, $remember = false);
    public function loginUsingId($id, $remember = false);
    public function viaRemember();
    public function logout();
}
namespace Illuminate\Contracts\Hashing;

interface Hasher
{
    public function make($value, array $options = array());
    public function check($value, $hashedValue, array $options = array());
    public function needsRehash($hashedValue, array $options = array());
}
namespace Illuminate\Auth;

use Illuminate\Support\Manager;
class AuthManager extends Manager
{
    protected function createDriver($driver)
    {
        $guard = parent::createDriver($driver);
        $guard->setCookieJar($this->app['cookie']);
        $guard->setDispatcher($this->app['events']);
        return $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
    }
    protected function callCustomCreator($driver)
    {
        $custom = parent::callCustomCreator($driver);
        if ($custom instanceof Guard) {
            return $custom;
        }
        return new Guard($custom, $this->app['session.store']);
    }
    public function createDatabaseDriver()
    {
        $provider = $this->createDatabaseProvider();
        return new Guard($provider, $this->app['session.store']);
    }
    protected function createDatabaseProvider()
    {
        $connection = $this->app['db']->connection();
        $table = $this->app['config']['auth.table'];
        return new DatabaseUserProvider($connection, $this->app['hash'], $table);
    }
    public function createEloquentDriver()
    {
        $provider = $this->createEloquentProvider();
        return new Guard($provider, $this->app['session.store']);
    }
    protected function createEloquentProvider()
    {
        $model = $this->app['config']['auth.model'];
        return new EloquentUserProvider($this->app['hash'], $model);
    }
    public function getDefaultDriver()
    {
        return $this->app['config']['auth.driver'];
    }
    public function setDefaultDriver($name)
    {
        $this->app['config']['auth.driver'] = $name;
    }
}
namespace Illuminate\Auth;

use RuntimeException;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Auth\UserProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Contracts\Auth\Guard as GuardContract;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJar;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
class Guard implements GuardContract
{
    protected $user;
    protected $lastAttempted;
    protected $viaRemember = false;
    protected $provider;
    protected $session;
    protected $cookie;
    protected $request;
    protected $events;
    protected $loggedOut = false;
    protected $tokenRetrievalAttempted = false;
    public function __construct(UserProvider $provider, SessionInterface $session, Request $request = null)
    {
        $this->session = $session;
        $this->request = $request;
        $this->provider = $provider;
    }
    public function check()
    {
        return !is_null($this->user());
    }
    public function guest()
    {
        return !$this->check();
    }
    public function user()
    {
        if ($this->loggedOut) {
            return;
        }
        if (!is_null($this->user)) {
            return $this->user;
        }
        $id = $this->session->get($this->getName());
        $user = null;
        if (!is_null($id)) {
            $user = $this->provider->retrieveById($id);
        }
        $recaller = $this->getRecaller();
        if (is_null($user) && !is_null($recaller)) {
            $user = $this->getUserByRecaller($recaller);
            if ($user) {
                $this->updateSession($user->getAuthIdentifier());
                $this->fireLoginEvent($user, true);
            }
        }
        return $this->user = $user;
    }
    public function id()
    {
        if ($this->loggedOut) {
            return;
        }
        $id = $this->session->get($this->getName(), $this->getRecallerId());
        if (is_null($id) && $this->user()) {
            $id = $this->user()->getAuthIdentifier();
        }
        return $id;
    }
    protected function getUserByRecaller($recaller)
    {
        if ($this->validRecaller($recaller) && !$this->tokenRetrievalAttempted) {
            $this->tokenRetrievalAttempted = true;
            list($id, $token) = explode('|', $recaller, 2);
            $this->viaRemember = !is_null($user = $this->provider->retrieveByToken($id, $token));
            return $user;
        }
    }
    protected function getRecaller()
    {
        return $this->request->cookies->get($this->getRecallerName());
    }
    protected function getRecallerId()
    {
        if ($this->validRecaller($recaller = $this->getRecaller())) {
            return head(explode('|', $recaller));
        }
    }
    protected function validRecaller($recaller)
    {
        if (!is_string($recaller) || !str_contains($recaller, '|')) {
            return false;
        }
        $segments = explode('|', $recaller);
        return count($segments) == 2 && trim($segments[0]) !== '' && trim($segments[1]) !== '';
    }
    public function once(array $credentials = array())
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);
            return true;
        }
        return false;
    }
    public function validate(array $credentials = array())
    {
        return $this->attempt($credentials, false, false);
    }
    public function basic($field = 'email')
    {
        if ($this->check()) {
            return;
        }
        if ($this->attemptBasic($this->getRequest(), $field)) {
            return;
        }
        return $this->getBasicResponse();
    }
    public function onceBasic($field = 'email')
    {
        if (!$this->once($this->getBasicCredentials($this->getRequest(), $field))) {
            return $this->getBasicResponse();
        }
    }
    protected function attemptBasic(Request $request, $field)
    {
        if (!$request->getUser()) {
            return false;
        }
        return $this->attempt($this->getBasicCredentials($request, $field));
    }
    protected function getBasicCredentials(Request $request, $field)
    {
        return array($field => $request->getUser(), 'password' => $request->getPassword());
    }
    protected function getBasicResponse()
    {
        $headers = array('WWW-Authenticate' => 'Basic');
        return new Response('Invalid credentials.', 401, $headers);
    }
    public function attempt(array $credentials = array(), $remember = false, $login = true)
    {
        $this->fireAttemptEvent($credentials, $remember, $login);
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            if ($login) {
                $this->login($user, $remember);
            }
            return true;
        }
        return false;
    }
    protected function hasValidCredentials($user, $credentials)
    {
        return !is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }
    protected function fireAttemptEvent(array $credentials, $remember, $login)
    {
        if ($this->events) {
            $payload = array($credentials, $remember, $login);
            $this->events->fire('auth.attempt', $payload);
        }
    }
    public function attempting($callback)
    {
        if ($this->events) {
            $this->events->listen('auth.attempt', $callback);
        }
    }
    public function login(UserContract $user, $remember = false)
    {
        $this->updateSession($user->getAuthIdentifier());
        if ($remember) {
            $this->createRememberTokenIfDoesntExist($user);
            $this->queueRecallerCookie($user);
        }
        $this->fireLoginEvent($user, $remember);
        $this->setUser($user);
    }
    protected function fireLoginEvent($user, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->fire('auth.login', array($user, $remember));
        }
    }
    protected function updateSession($id)
    {
        $this->session->set($this->getName(), $id);
        $this->session->migrate(true);
    }
    public function loginUsingId($id, $remember = false)
    {
        $this->session->set($this->getName(), $id);
        $this->login($user = $this->provider->retrieveById($id), $remember);
        return $user;
    }
    public function onceUsingId($id)
    {
        $this->setUser($this->provider->retrieveById($id));
        return $this->user instanceof UserContract;
    }
    protected function queueRecallerCookie(UserContract $user)
    {
        $value = $user->getAuthIdentifier() . '|' . $user->getRememberToken();
        $this->getCookieJar()->queue($this->createRecaller($value));
    }
    protected function createRecaller($value)
    {
        return $this->getCookieJar()->forever($this->getRecallerName(), $value);
    }
    public function logout()
    {
        $user = $this->user();
        $this->clearUserDataFromStorage();
        if (!is_null($this->user)) {
            $this->refreshRememberToken($user);
        }
        if (isset($this->events)) {
            $this->events->fire('auth.logout', array($user));
        }
        $this->user = null;
        $this->loggedOut = true;
    }
    protected function clearUserDataFromStorage()
    {
        $this->session->remove($this->getName());
        $recaller = $this->getRecallerName();
        $this->getCookieJar()->queue($this->getCookieJar()->forget($recaller));
    }
    protected function refreshRememberToken(UserContract $user)
    {
        $user->setRememberToken($token = str_random(60));
        $this->provider->updateRememberToken($user, $token);
    }
    protected function createRememberTokenIfDoesntExist(UserContract $user)
    {
        $rememberToken = $user->getRememberToken();
        if (empty($rememberToken)) {
            $this->refreshRememberToken($user);
        }
    }
    public function getCookieJar()
    {
        if (!isset($this->cookie)) {
            throw new RuntimeException('Cookie jar has not been set.');
        }
        return $this->cookie;
    }
    public function setCookieJar(CookieJar $cookie)
    {
        $this->cookie = $cookie;
    }
    public function getDispatcher()
    {
        return $this->events;
    }
    public function setDispatcher(Dispatcher $events)
    {
        $this->events = $events;
    }
    public function getSession()
    {
        return $this->session;
    }
    public function getProvider()
    {
        return $this->provider;
    }
    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;
    }
    public function getUser()
    {
        return $this->user;
    }
    public function setUser(UserContract $user)
    {
        $this->user = $user;
        $this->loggedOut = false;
    }
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }
    public function setRequest(Request $request)
    {
        $this->request = $request;
        return $this;
    }
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }
    public function getName()
    {
        return 'login_' . md5(get_class($this));
    }
    public function getRecallerName()
    {
        return 'remember_' . md5(get_class($this));
    }
    public function viaRemember()
    {
        return $this->viaRemember;
    }
}
namespace Illuminate\Contracts\Auth;

interface UserProvider
{
    public function retrieveById($identifier);
    public function retrieveByToken($identifier, $token);
    public function updateRememberToken(Authenticatable $user, $token);
    public function retrieveByCredentials(array $credentials);
    public function validateCredentials(Authenticatable $user, array $credentials);
}
namespace Illuminate\Auth;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;
class EloquentUserProvider implements UserProvider
{
    protected $hasher;
    protected $model;
    public function __construct(HasherContract $hasher, $model)
    {
        $this->model = $model;
        $this->hasher = $hasher;
    }
    public function retrieveById($identifier)
    {
        return $this->createModel()->newQuery()->find($identifier);
    }
    public function retrieveByToken($identifier, $token)
    {
        $model = $this->createModel();
        return $model->newQuery()->where($model->getKeyName(), $identifier)->where($model->getRememberTokenName(), $token)->first();
    }
    public function updateRememberToken(UserContract $user, $token)
    {
        $user->setRememberToken($token);
        $user->save();
    }
    public function retrieveByCredentials(array $credentials)
    {
        $query = $this->createModel()->newQuery();
        foreach ($credentials as $key => $value) {
            if (!str_contains($key, 'password')) {
                $query->where($key, $value);
            }
        }
        return $query->first();
    }
    public function validateCredentials(UserContract $user, array $credentials)
    {
        $plain = $credentials['password'];
        return $this->hasher->check($plain, $user->getAuthPassword());
    }
    public function createModel()
    {
        $class = '\\' . ltrim($this->model, '\\');
        return new $class();
    }
}
namespace Illuminate\Container;

use Closure;
use ArrayAccess;
use ReflectionClass;
use ReflectionMethod;
use ReflectionFunction;
use ReflectionParameter;
use InvalidArgumentException;
use Illuminate\Contracts\Container\Container as ContainerContract;
class Container implements ArrayAccess, ContainerContract
{
    protected static $instance;
    protected $resolved = array();
    protected $bindings = array();
    protected $instances = array();
    protected $aliases = array();
    protected $extenders = array();
    protected $tags = array();
    protected $buildStack = array();
    public $contextual = array();
    protected $reboundCallbacks = array();
    protected $globalResolvingCallbacks = array();
    protected $globalAfterResolvingCallbacks = array();
    protected $resolvingCallbacks = array();
    protected $afterResolvingCallbacks = array();
    public function when($concrete)
    {
        return new ContextualBindingBuilder($this, $concrete);
    }
    protected function resolvable($abstract)
    {
        return $this->bound($abstract);
    }
    public function bound($abstract)
    {
        return isset($this->bindings[$abstract]) || isset($this->instances[$abstract]) || $this->isAlias($abstract);
    }
    public function resolved($abstract)
    {
        return isset($this->resolved[$abstract]) || isset($this->instances[$abstract]);
    }
    public function isAlias($name)
    {
        return isset($this->aliases[$name]);
    }
    public function bind($abstract, $concrete = null, $shared = false)
    {
        if (is_array($abstract)) {
            list($abstract, $alias) = $this->extractAlias($abstract);
            $this->alias($abstract, $alias);
        }
        $this->dropStaleInstances($abstract);
        if (is_null($concrete)) {
            $concrete = $abstract;
        }
        if (!$concrete instanceof Closure) {
            $concrete = $this->getClosure($abstract, $concrete);
        }
        $this->bindings[$abstract] = compact('concrete', 'shared');
        if ($this->resolved($abstract)) {
            $this->rebound($abstract);
        }
    }
    protected function getClosure($abstract, $concrete)
    {
        return function ($c, $parameters = array()) use($abstract, $concrete) {
            $method = $abstract == $concrete ? 'build' : 'make';
            return $c->{$method}($concrete, $parameters);
        };
    }
    public function addContextualBinding($concrete, $abstract, $implementation)
    {
        $this->contextual[$concrete][$abstract] = $implementation;
    }
    public function bindIf($abstract, $concrete = null, $shared = false)
    {
        if (!$this->bound($abstract)) {
            $this->bind($abstract, $concrete, $shared);
        }
    }
    public function singleton($abstract, $concrete = null)
    {
        $this->bind($abstract, $concrete, true);
    }
    public function share(Closure $closure)
    {
        return function ($container) use($closure) {
            static $object;
            if (is_null($object)) {
                $object = $closure($container);
            }
            return $object;
        };
    }
    public function bindShared($abstract, Closure $closure)
    {
        $this->bind($abstract, $this->share($closure), true);
    }
    public function extend($abstract, Closure $closure)
    {
        if (isset($this->instances[$abstract])) {
            $this->instances[$abstract] = $closure($this->instances[$abstract], $this);
            $this->rebound($abstract);
        } else {
            $this->extenders[$abstract][] = $closure;
        }
    }
    public function instance($abstract, $instance)
    {
        if (is_array($abstract)) {
            list($abstract, $alias) = $this->extractAlias($abstract);
            $this->alias($abstract, $alias);
        }
        unset($this->aliases[$abstract]);
        $bound = $this->bound($abstract);
        $this->instances[$abstract] = $instance;
        if ($bound) {
            $this->rebound($abstract);
        }
    }
    public function tag($abstracts, $tags)
    {
        $tags = is_array($tags) ? $tags : array_slice(func_get_args(), 1);
        foreach ($tags as $tag) {
            if (!isset($this->tags[$tag])) {
                $this->tags[$tag] = array();
            }
            foreach ((array) $abstracts as $abstract) {
                $this->tags[$tag][] = $abstract;
            }
        }
    }
    public function tagged($tag)
    {
        $results = array();
        foreach ($this->tags[$tag] as $abstract) {
            $results[] = $this->make($abstract);
        }
        return $results;
    }
    public function alias($abstract, $alias)
    {
        $this->aliases[$alias] = $abstract;
    }
    protected function extractAlias(array $definition)
    {
        return array(key($definition), current($definition));
    }
    public function rebinding($abstract, Closure $callback)
    {
        $this->reboundCallbacks[$abstract][] = $callback;
        if ($this->bound($abstract)) {
            return $this->make($abstract);
        }
    }
    public function refresh($abstract, $target, $method)
    {
        return $this->rebinding($abstract, function ($app, $instance) use($target, $method) {
            $target->{$method}($instance);
        });
    }
    protected function rebound($abstract)
    {
        $instance = $this->make($abstract);
        foreach ($this->getReboundCallbacks($abstract) as $callback) {
            call_user_func($callback, $this, $instance);
        }
    }
    protected function getReboundCallbacks($abstract)
    {
        if (isset($this->reboundCallbacks[$abstract])) {
            return $this->reboundCallbacks[$abstract];
        }
        return array();
    }
    public function wrap(Closure $callback, array $parameters = array())
    {
        return function () use($callback, $parameters) {
            return $this->call($callback, $parameters);
        };
    }
    public function call($callback, array $parameters = array(), $defaultMethod = null)
    {
        if ($this->isCallableWithAtSign($callback) || $defaultMethod) {
            return $this->callClass($callback, $parameters, $defaultMethod);
        }
        $dependencies = $this->getMethodDependencies($callback, $parameters);
        return call_user_func_array($callback, $dependencies);
    }
    protected function isCallableWithAtSign($callback)
    {
        if (!is_string($callback)) {
            return false;
        }
        return strpos($callback, '@') !== false;
    }
    protected function getMethodDependencies($callback, $parameters = array())
    {
        $dependencies = array();
        foreach ($this->getCallReflector($callback)->getParameters() as $key => $parameter) {
            $this->addDependencyForCallParameter($parameter, $parameters, $dependencies);
        }
        return array_merge($dependencies, $parameters);
    }
    protected function getCallReflector($callback)
    {
        if (is_string($callback) && strpos($callback, '::') !== false) {
            $callback = explode('::', $callback);
        }
        if (is_array($callback)) {
            return new ReflectionMethod($callback[0], $callback[1]);
        }
        return new ReflectionFunction($callback);
    }
    protected function addDependencyForCallParameter(ReflectionParameter $parameter, array &$parameters, &$dependencies)
    {
        if (array_key_exists($parameter->name, $parameters)) {
            $dependencies[] = $parameters[$parameter->name];
            unset($parameters[$parameter->name]);
        } elseif ($parameter->getClass()) {
            $dependencies[] = $this->make($parameter->getClass()->name);
        } elseif ($parameter->isDefaultValueAvailable()) {
            $dependencies[] = $parameter->getDefaultValue();
        }
    }
    protected function callClass($target, array $parameters = array(), $defaultMethod = null)
    {
        $segments = explode('@', $target);
        $method = count($segments) == 2 ? $segments[1] : $defaultMethod;
        if (is_null($method)) {
            throw new InvalidArgumentException('Method not provided.');
        }
        return $this->call(array($this->make($segments[0]), $method), $parameters);
    }
    public function make($abstract, $parameters = array())
    {
        $abstract = $this->getAlias($abstract);
        if (isset($this->instances[$abstract])) {
            return $this->instances[$abstract];
        }
        $concrete = $this->getConcrete($abstract);
        if ($this->isBuildable($concrete, $abstract)) {
            $object = $this->build($concrete, $parameters);
        } else {
            $object = $this->make($concrete, $parameters);
        }
        foreach ($this->getExtenders($abstract) as $extender) {
            $object = $extender($object, $this);
        }
        if ($this->isShared($abstract)) {
            $this->instances[$abstract] = $object;
        }
        $this->fireResolvingCallbacks($abstract, $object);
        $this->resolved[$abstract] = true;
        return $object;
    }
    protected function getConcrete($abstract)
    {
        if (!is_null($concrete = $this->getContextualConcrete($abstract))) {
            return $concrete;
        }
        if (!isset($this->bindings[$abstract])) {
            if ($this->missingLeadingSlash($abstract) && isset($this->bindings['\\' . $abstract])) {
                $abstract = '\\' . $abstract;
            }
            return $abstract;
        }
        return $this->bindings[$abstract]['concrete'];
    }
    protected function getContextualConcrete($abstract)
    {
        if (isset($this->contextual[end($this->buildStack)][$abstract])) {
            return $this->contextual[end($this->buildStack)][$abstract];
        }
    }
    protected function missingLeadingSlash($abstract)
    {
        return is_string($abstract) && strpos($abstract, '\\') !== 0;
    }
    protected function getExtenders($abstract)
    {
        if (isset($this->extenders[$abstract])) {
            return $this->extenders[$abstract];
        }
        return array();
    }
    public function build($concrete, $parameters = array())
    {
        if ($concrete instanceof Closure) {
            return $concrete($this, $parameters);
        }
        $reflector = new ReflectionClass($concrete);
        if (!$reflector->isInstantiable()) {
            $message = "Target [{$concrete}] is not instantiable.";
            throw new BindingResolutionException($message);
        }
        $this->buildStack[] = $concrete;
        $constructor = $reflector->getConstructor();
        if (is_null($constructor)) {
            array_pop($this->buildStack);
            return new $concrete();
        }
        $dependencies = $constructor->getParameters();
        $parameters = $this->keyParametersByArgument($dependencies, $parameters);
        $instances = $this->getDependencies($dependencies, $parameters);
        array_pop($this->buildStack);
        return $reflector->newInstanceArgs($instances);
    }
    protected function getDependencies($parameters, array $primitives = array())
    {
        $dependencies = array();
        foreach ($parameters as $parameter) {
            $dependency = $parameter->getClass();
            if (array_key_exists($parameter->name, $primitives)) {
                $dependencies[] = $primitives[$parameter->name];
            } elseif (is_null($dependency)) {
                $dependencies[] = $this->resolveNonClass($parameter);
            } else {
                $dependencies[] = $this->resolveClass($parameter);
            }
        }
        return (array) $dependencies;
    }
    protected function resolveNonClass(ReflectionParameter $parameter)
    {
        if ($parameter->isDefaultValueAvailable()) {
            return $parameter->getDefaultValue();
        }
        $message = "Unresolvable dependency resolving [{$parameter}] in class {$parameter->getDeclaringClass()->getName()}";
        throw new BindingResolutionException($message);
    }
    protected function resolveClass(ReflectionParameter $parameter)
    {
        try {
            return $this->make($parameter->getClass()->name);
        } catch (BindingResolutionException $e) {
            if ($parameter->isOptional()) {
                return $parameter->getDefaultValue();
            }
            throw $e;
        }
    }
    protected function keyParametersByArgument(array $dependencies, array $parameters)
    {
        foreach ($parameters as $key => $value) {
            if (is_numeric($key)) {
                unset($parameters[$key]);
                $parameters[$dependencies[$key]->name] = $value;
            }
        }
        return $parameters;
    }
    public function resolving($abstract, Closure $callback = null)
    {
        if ($callback === null && $abstract instanceof Closure) {
            $this->resolvingCallback($abstract);
        } else {
            $this->resolvingCallbacks[$abstract][] = $callback;
        }
    }
    public function afterResolving($abstract, Closure $callback = null)
    {
        if ($abstract instanceof Closure && $callback === null) {
            $this->afterResolvingCallback($abstract);
        } else {
            $this->afterResolvingCallbacks[$abstract][] = $callback;
        }
    }
    protected function resolvingCallback(Closure $callback)
    {
        $abstract = $this->getFunctionHint($callback);
        if ($abstract) {
            $this->resolvingCallbacks[$abstract][] = $callback;
        } else {
            $this->globalResolvingCallbacks[] = $callback;
        }
    }
    protected function afterResolvingCallback(Closure $callback)
    {
        $abstract = $this->getFunctionHint($callback);
        if ($abstract) {
            $this->afterResolvingCallbacks[$abstract][] = $callback;
        } else {
            $this->globalAfterResolvingCallbacks[] = $callback;
        }
    }
    protected function getFunctionHint(Closure $callback)
    {
        $function = new ReflectionFunction($callback);
        if ($function->getNumberOfParameters() == 0) {
            return null;
        }
        $expected = $function->getParameters()[0];
        if (!$expected->getClass()) {
            return null;
        }
        return $expected->getClass()->name;
    }
    protected function fireResolvingCallbacks($abstract, $object)
    {
        $this->fireCallbackArray($object, $this->globalResolvingCallbacks);
        $this->fireCallbackArray($object, $this->getCallbacksForType($abstract, $object, $this->resolvingCallbacks));
        $this->fireCallbackArray($object, $this->globalAfterResolvingCallbacks);
        $this->fireCallbackArray($object, $this->getCallbacksForType($abstract, $object, $this->afterResolvingCallbacks));
    }
    protected function getCallbacksForType($abstract, $object, array $callbacksPerType)
    {
        $results = array();
        foreach ($callbacksPerType as $type => $callbacks) {
            if ($type === $abstract || $object instanceof $type) {
                $results = array_merge($results, $callbacks);
            }
        }
        return $results;
    }
    protected function fireCallbackArray($object, array $callbacks)
    {
        foreach ($callbacks as $callback) {
            $callback($object, $this);
        }
    }
    public function isShared($abstract)
    {
        if (isset($this->bindings[$abstract]['shared'])) {
            $shared = $this->bindings[$abstract]['shared'];
        } else {
            $shared = false;
        }
        return isset($this->instances[$abstract]) || $shared === true;
    }
    protected function isBuildable($concrete, $abstract)
    {
        return $concrete === $abstract || $concrete instanceof Closure;
    }
    protected function getAlias($abstract)
    {
        return isset($this->aliases[$abstract]) ? $this->aliases[$abstract] : $abstract;
    }
    public function getBindings()
    {
        return $this->bindings;
    }
    protected function dropStaleInstances($abstract)
    {
        unset($this->instances[$abstract], $this->aliases[$abstract]);
    }
    public function forgetInstance($abstract)
    {
        unset($this->instances[$abstract]);
    }
    public function forgetInstances()
    {
        $this->instances = array();
    }
    public function flush()
    {
        $this->aliases = array();
        $this->resolved = array();
        $this->bindings = array();
        $this->instances = array();
    }
    public static function getInstance()
    {
        return static::$instance;
    }
    public static function setInstance(ContainerContract $container)
    {
        static::$instance = $container;
    }
    public function offsetExists($key)
    {
        return isset($this->bindings[$key]);
    }
    public function offsetGet($key)
    {
        return $this->make($key);
    }
    public function offsetSet($key, $value)
    {
        if (!$value instanceof Closure) {
            $value = function () use($value) {
                return $value;
            };
        }
        $this->bind($key, $value);
    }
    public function offsetUnset($key)
    {
        unset($this->bindings[$key], $this->instances[$key], $this->resolved[$key]);
    }
    public function __get($key)
    {
        return $this[$key];
    }
    public function __set($key, $value)
    {
        $this[$key] = $value;
    }
}
namespace Symfony\Component\HttpKernel;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
interface HttpKernelInterface
{
    const MASTER_REQUEST = 1;
    const SUB_REQUEST = 2;
    public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = true);
}
namespace Symfony\Component\HttpKernel;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
interface TerminableInterface
{
    public function terminate(Request $request, Response $response);
}
