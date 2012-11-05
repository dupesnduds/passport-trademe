/**
 * Module dependencies.
 */
var util = require('util')
	, OAuthStrategy = require('passport-oauth').OAuthStrategy
	, InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {

	options = options || {};
	options.requestTokenURL = options.requestTokenURL || 'https://secure.trademe.co.nz/Oauth/RequestToken';
	options.accessTokenURL = options.accessTokenURL || 'https://secure.trademe.co.nz/Oauth/AccessToken';
	options.userAuthorizationURL = options.userAuthorizationURL || 'https://secure.trademe.co.nz/Oauth/Authorize';
	options.sessionKey = options.sessionKey || 'oauth:trademe';
	
	OAuthStrategy.call(this, options, verify);
	this.name = 'trademe';
	
	this._skipExtendedUserProfile = (options.skipExtendedUserProfile === undefined) ? false : options.skipExtendedUserProfile;
}

/**
 * Inherit from `OAuthStrategy`.
 */
util.inherits(Strategy, OAuthStrategy);


/**
 * Authenticate request by delegating to Trademe using OAuth.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
	// authentication failure.
	if (req.query && req.query.denied) {
		return this.fail();
	}
	
	// Call the base class for standard OAuth authentication.
	OAuthStrategy.prototype.authenticate.call(this, req, options);
}

/**
 * Retrieve member profile from Trademe.
 *
 * http://api.trademe.co.nz/v1/Member/Profile.json
 * { "Id": 5690 }
 *
 * http://api.trademe.co.nz/v1/Member/5690/Profile.json
 * { 
 * "Biography" : "",
 * "DateRemoved" : "/Date(0)/",
 * "FirstName" : "Karol",
 * "IsEnabled" : true,
 * "Member" : { "DateAddressVerified" : "/Date(0)/",
 *     "DateJoined" : "/Date(946551600000)/",
 *     "FeedbackCount" : 20,
 *     "IsAddressVerified" : false,
 *     "IsAuthenticated" : true,
 *     "IsDealer" : false,
 *     "MemberId" : 5690,
 *     "Nickname" : "silverhalides",
 *     "Suburb" : "Wellington City",
 *     "UniqueNegative" : 0,
 *     "UniquePositive" : 20
 *   },
 * "Occupation" : "",
 * "Photo" : "http://images.trademe.co.nz/photoserver/profiles/member_profile5690v1",
 * "Quote" : ""
 * }
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(token, tokenSecret, params, done) {
	
	var profile = { provider: 'trademe' };
	
	if (!this._skipExtendedUserProfile) {
		
		var url = 'http://api.trademe.co.nz/v1/Member/Profile.json';
		this._oauth.get(url, token, tokenSecret, function (err, body, res) {

			if (err) { return done(new InternalOAuthError('failed to fetch member profile', err)); }
			
			var object = {};
			
			try {
				object = JSON.parse(body);
			} catch (e) {
				object = null;
				done(e);
			}
			
			if (object === undefined || object === null) {
				console.log('Unfortunately the object is non-existent');
			} else {
				profile.id = object.Id;
				profile._raw = body;
				profile._json = object;
				
				done(null, profile);
			} 
		});
	} else {
		profile.id = params.user_id;
		
		done(null, profile);
	}
}

//
Strategy.prototype.requestTokenParams = function(options) {
  var params = options || {};
  
  var scope = options.scope;
  if (scope) {
    if (Array.isArray(scope)) { scope = scope.join(' '); }
    params['scope'] = scope;
  }
  return params;
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
