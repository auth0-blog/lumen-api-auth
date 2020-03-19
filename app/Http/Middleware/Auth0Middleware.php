<?php

namespace App\Http\Middleware;

use Closure;
use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Helpers\JWKFetcher;
use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\TokenVerifier;


class Auth0Middleware
{
    /**
     * Run the request filter.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next, $scopeRequired = null)
    {
        $token = $request->bearerToken();

        if(!$token) {
            return response()->json('No token provided', 401);
        }

        $this->validateAndDecode($token);
        $decodedToken = $this->validateAndDecode($token);
        if ($scopeRequired && !$this->tokenHasScope($decodedToken, $scopeRequired)) {
            return response()->json(['message' => 'Insufficient scope'], 403);
        }
        return $next($request);
    }

    public function validateAndDecode($token)
    {
        try {
            $jwksUri = env('AUTH0_DOMAIN') . '.well-known/jwks.json';
    
            $jwksFetcher = new JWKFetcher(null, [ 'base_uri' => $jwksUri ]);
            $signatureVerifier = new AsymmetricVerifier($jwksFetcher);
            $tokenVerifier = new TokenVerifier(env('AUTH0_DOMAIN'), env('AUTH0_AUD'), $signatureVerifier);

            return $tokenVerifier->verify($token);
        }
        catch(InvalidTokenException $e) {
            throw $e;
        };
    }

    /**
     * Check if a token has a specific scope.
     *
     * @param \stdClass $token - JWT access token to check.
     * @param string $scopeRequired - Scope to check for.
     *
     * @return bool
     */
    protected function tokenHasScope($token, $scopeRequired)
    {
        if (empty($token['scope'])) {
            return false;
        }

        $tokenScopes = explode(' ', $token['scope']);

        return in_array($scopeRequired, $tokenScopes);
    }
  
}