<?php
declare(strict_types=1);

namespace Fx\SessionGuard;

use Fx\HyperfHttpAuth\Annotation\GuardAnnotation;
use Fx\HyperfHttpAuth\Contract\Authenticatable;
use Fx\HyperfHttpAuth\Contract\StatefulGuard;
use Fx\HyperfHttpAuth\Contract\UserProvider;
use Fx\HyperfHttpAuth\Recaller;
use Fx\HyperfHttpAuth\GuardHelpers;
use Fx\HyperfHttpAuth\Exception\UnauthorizedHttpException;
use Hyperf\Contract\SessionInterface;
use Hyperf\Di\Annotation\Inject;
use Hyperf\HttpMessage\Cookie\CookieJarInterface;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Utils\Str;
use Fangx\Cookie\Contracts\QueueingFactory;

/**
 * Class SessionGuard
 * @package Fx\SessionGuard
 *
 * @GuardAnnotation("session")
 */
class SessionGuard implements StatefulGuard
{
    use GuardHelpers;

    /**
     * The name of the Guard. Typically "session".
     *
     * Corresponds to guard name in authentication configuration.
     *
     * @var string
     */
    protected $name = "session";

    /**
     * The user we last attempted to retrieve.
     *
     * @var Authenticatable
     */
    protected $lastAttempted;

    /**
     * Indicates if the user was authenticated via a recaller cookie.
     *
     * @var bool
     */
    protected $viaRemember = false;

    /**
     * The session used by the guard.
     *
     * @var \Hyperf\Contract\SessionInterface
     */
    protected $session;

    /**
     *  The cookie creator service.
     *
     * @var \Fangx\Cookie\Contracts\QueueingFactory
     */
    protected $cookie;

    /**
     * The request instance.
     *
     * @var RequestInterface
     */
    protected $request;

    /**
     * Indicates if the logout method has been called.
     *
     * @var bool
     */
    protected $loggedOut = false;

    /**
     * Indicates if a token user retrieval has been attempted.
     *
     * @var bool
     */
    protected $recallAttempted = false;

    /**
     * Create a new authentication guard.
     *
     * @param array $config
     * @param UserProvider $provider
     * @return void
     */
    public function __construct($config, UserProvider $provider)
    {
        $this->provider = $provider;
        $this->session = make(SessionInterface::class);
        $this->cookie = make(QueueingFactory::class);
    }

    /**
     * Get the currently authenticated user.
     *
     * @return Authenticatable|null
     */
    public function user()
    {
        if ($this->loggedOut) {
            return;
        }

        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (!is_null($this->user)) {
            return $this->user;
        }

        $id = $this->session->get($this->getName());

        if (!is_null($id) && $this->user = $this->provider->retrieveById($id)) {
            // 触发事件
        }

        if (is_null($this->user) && !is_null($recaller = $this->recaller())) {
            $this->user = $this->userFromRecaller($recaller);
            if ($this->user) {
                $this->updateSession($this->user->getAuthIdentifier());
            }
        }

        return $this->user;
    }

    /**
     * Pull a user from the repository by its "remember me" cookie token.
     *
     * @param $recaller
     * @return mixed
     */
    protected function userFromRecaller($recaller)
    {
        if (!$recaller->valid() || $this->recallAttempted) {
            return;
        }

        // If the user is null, but we decrypt a "recaller" cookie we can attempt to
        // pull the user data on that cookie which serves as a remember cookie on
        // the application. Once we have a user we can return it to the caller.
        $this->recallAttempted = true;

        $this->viaRemember = !is_null($user = $this->provider->retrieveByToken(
            $recaller->id(), $recaller->token()
        ));

        return $user;
    }

    /**
     * Get the decrypted recaller cookie for the request.
     *
     * @return null
     */
    protected function recaller()
    {
        if (is_null($this->request)) {
            return;
        }

        if ($recaller = $this->request->cookie($this->getRecallerName())) {
            return new Recaller($recaller);
        }
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|null
     */
    public function id()
    {
        if ($this->loggedOut) {
            return;
        }

        return $this->user()
            ? $this->user()->getAuthIdentifier()
            : $this->session->get($this->getName());
    }

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param array $credentials
     * @return bool
     */
    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param mixed $id
     * @return Authenticatable|false
     */
    public function onceUsingId($id)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return $user;
        }

        return false;
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        return $this->hasValidCredentials($user, $credentials);
    }

    /**
     * Attempt to authenticate using HTTP Basic Auth.
     *
     * @param string $field
     * @param array $extraConditions
     * @return ResponseInterface|null
     */
    public function basic($field = 'email', $extraConditions = [])
    {
        if ($this->check()) {
            return;
        }

        // If a username is set on the HTTP basic request, we will return out without
        // interrupting the request lifecycle. Otherwise, we'll need to generate a
        // request indicating that the given credentials were invalid for login.
        if ($this->attemptBasic($this->getRequest(), $field, $extraConditions)) {
            return;
        }

        return $this->failedBasicResponse();
    }

    /**
     * Perform a stateless HTTP Basic login attempt.
     *
     * @param string $field
     * @param array $extraConditions
     * @return ResponseInterface|null
     */
    public function onceBasic($field = 'email', $extraConditions = [])
    {
        $credentials = $this->basicCredentials($this->getRequest(), $field);

        if (!$this->once(array_merge($credentials, $extraConditions))) {
            return $this->failedBasicResponse();
        }
    }

    /**
     * Attempt to authenticate using basic authentication.
     *
     * @param RequestInterface $request
     * @param string $field
     * @param array $extraConditions
     * @return bool
     */
    protected function attemptBasic(RequestInterface $request, $field, $extraConditions = [])
    {
        if (!$request->getUser()) {
            return false;
        }

        return $this->attempt(array_merge(
            $this->basicCredentials($request, $field), $extraConditions
        ));
    }

    /**
     * Get the credential array for a HTTP Basic request.
     *
     * @param RequestInterface $request
     * @param string $field
     * @return array
     */
    protected function basicCredentials(RequestInterface $request, $field)
    {
        return [$field => $request->getUser(), 'password' => $request->getPassword()];
    }

    /**
     * Get the response for basic authentication.
     *
     * @return void
     *
     * @throws UnauthorizedHttpException
     */
    protected function failedBasicResponse()
    {
        throw new UnauthorizedHttpException('Basic', 'Invalid credentials.');
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param array $credentials
     * @param bool $remember
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);

            return true;
        }

        return false;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param mixed $user
     * @param array $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return !is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Log the given user ID into the application.
     *
     * @param mixed $id
     * @param bool $remember
     * @return Authenticatable|false
     */
    public function loginUsingId($id, $remember = false)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    /**
     * Log a user into the application.
     *
     * @param Authenticatable $user
     * @param bool $remember
     * @return void
     */
    public function login(Authenticatable $user, $remember = false)
    {
        $this->updateSession($user->getAuthIdentifier());

        // If the user should be permanently "remembered" by the application we will
        // queue a permanent cookie that contains the encrypted copy of the user
        // identifier. We will then decrypt this later to retrieve the users.
        if ($remember) {
            $this->ensureRememberTokenIsSet($user);

            $this->queueRecallerCookie($user);
        }

        $this->setUser($user);
    }

    /**
     * Update the session with the given ID.
     *
     * @param string $id
     * @return void
     */
    protected function updateSession($id)
    {
        $this->session->put($this->getName(), $id);

        $this->session->migrate(true);
    }

    /**
     * Create a new "remember me" token for the user if one doesn't already exist.
     *
     * @param Authenticatable $user
     * @return void
     */
    protected function ensureRememberTokenIsSet(Authenticatable $user)
    {
        if (empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }
    }

    /**
     * Queue the recaller cookie into the cookie jar.
     *
     * @param Authenticatable $user
     * @return void
     */
    protected function queueRecallerCookie(Authenticatable $user)
    {
        $this->getCookieJar()->queue($this->createRecaller(
            $user->getAuthIdentifier() . '|' . $user->getRememberToken() . '|' . $user->getAuthPassword()
        ));
    }

    /**
     * Create a "remember me" cookie for a given ID.
     *
     * @param string $value
     * @return mixed
     */
    protected function createRecaller($value)
    {
        return $this->getCookieJar()->forever($this->getRecallerName(), $value);
    }

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        $user = $this->user();

        $this->clearUserDataFromStorage();

        if (!is_null($this->user) && !empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }

        // Once we have fired the logout event we will clear the users out of memory
        // so they are no longer available as the user is no longer considered as
        // being signed into this application and should not be available here.
        $this->user = null;

        $this->loggedOut = true;
    }

    /**
     * Remove the user data from the session and cookies.
     *
     * @return void
     */
    protected function clearUserDataFromStorage()
    {
        $this->session->remove($this->getName());

        if (!is_null($this->recaller())) {
            $this->getCookieJar()->queue($this->getCookieJar()
                ->forget($this->getRecallerName()));
        }
    }

    /**
     * Refresh the "remember me" token for the user.
     *
     * @param Authenticatable $user
     * @return void
     */
    protected function cycleRememberToken(Authenticatable $user)
    {
        $user->setRememberToken($token = Str::random(60));

        $this->provider->updateRememberToken($user, $token);
    }

    /**
     * Log the user out of the application on their current device only.
     *
     * @return void
     */
    public function logoutCurrentDevice()
    {
        $user = $this->user();

        $this->clearUserDataFromStorage();

        $this->user = null;

        $this->loggedOut = true;
    }

    /**
     * Invalidate other sessions for the current user.
     *
     * The application must be using the AuthenticateSession middleware.
     *
     * @param string $password
     * @param string $attribute
     * @return bool|null
     */
    public function logoutOtherDevices($password, $attribute = 'password')
    {
        if (!$this->user()) {
            return;
        }

        $result = tap($this->user()->forceFill([
            $attribute => bcrypt($password),
        ]))->save();

        if ($this->recaller() ||
            $this->getCookieJar()->hasQueued($this->getRecallerName())) {
            $this->queueRecallerCookie($this->user());
        }

        return $result;
    }

    /**
     * Get the last user we attempted to authenticate.
     *
     * @return Authenticatable
     */
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }

    /**
     * Get a unique identifier for the auth session value.
     *
     * @return string
     */
    public function getName()
    {
        return 'login_' . $this->name . '_' . sha1(static::class);
    }

    /**
     * Get the name of the cookie used to store the "recaller".
     *
     * @return string
     */
    public function getRecallerName()
    {
        return 'remember_' . $this->name . '_' . sha1(static::class);
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     *
     * @return bool
     */
    public function viaRemember()
    {
        return $this->viaRemember;
    }

    /**
     * Return the currently cached user.
     *
     * @return Authenticatable|null
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param Authenticatable $user
     * @return $this
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;

        $this->loggedOut = false;

        return $this;
    }

    /**
     * Get the cookie creator instance used by the guard.
     *
     * @return CookieJarInterface
     *
     * @throws \RuntimeException
     */
    public function getCookieJar()
    {
        if (!isset($this->cookie)) {
            throw new \RuntimeException('Cookie jar has not been set.');
        }

        return $this->cookie;
    }

    /**
     * Set the cookie creator instance used by the guard.
     *
     * @param CookieJarInterface $cookie
     * @return void
     */
    public function setCookieJar(CookieJarInterface $cookie)
    {
        $this->cookie = $cookie;
    }

    protected function fireEvent($event, ...$args)
    {
        new $event(...$args);
    }
}