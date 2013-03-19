<?php
/**
 * CloudFlare API
 * 
 * 
 * @author AzzA <azza@broadcasthe.net>
 * @copyright omgwtfhax inc. 2011
 * @version 1.0
 */
class cloudflare_api {
    //The URL of the API
    private $URL = array('USER' => 'https://www.cloudflare.com/api_json.html', 'HOST' => 'https://api.cloudflare.com/host-gw.html');
    
    //Timeout for the API requests in seconds
    const TIMEOUT = 5;

    //Interval values for Stats
    const INTERVAL_365_DAYS = 10;
    const INTERVAL_30_DAYS = 20;
    const INTERVAL_7_DAYS = 30;
    const INTERVAL_DAY = 40;
    const INTERVAL_24_HOURS = 100;
    const INTERVAL_12_HOURS = 110;
    const INTERVAL_6_HOURS = 120;
    
    //Stores the api key
    private $token_key;
    private $host_key;
    
    //Stores the email login
    private $email;
    
    //Data to post
    private $data = array();
    
    /**
     * Make a new instance of the API client
     */
    public function __construct() {
        $parameters = func_get_args();
        switch (func_num_args()) {
            case 1:
                //a host API
                $this->host_key  = $parameters[0];
                break;
            case 2:
                //a user request
                $this->email     = $parameters[0];
                $this->token_key = $parameters[1];
                break;
        }
    }
    
    public function setEmail($email) {
        $this->email = $email;
    }
    
    public function setToken($token_key) {
        $this->token_key = $token_key;
    }
    
	
    /**
     * CLIENT API
     * Section 3
     * Access
     */
	
    /**
     * 3.1 - Retrieve Domain Statistics For A Given Time Frame
     * This function retrieves the current stats and settings for a particular website.
     * It can also be used to get currently settings of values such as the security level.
     */
    public function stats($domain, $interval = 20) {
        $data['a']        = "stats";
        $data['z']        = $domain;
        $data['interval'] = $interval;
        return $this->http_post($data);
    }
	
    /**
     * 3.4 - Checks For Active Zones And Returns Their Corresponding Zids
     * This function retrieves domain statistics for a given time frame.
     */
    public function zone_check($zones) {
        if (is_array($zones))
            $zones = implode(",", $zones);
        $data['a']     = 'zone_check';
        $data['zones'] = $zones;
        return $this->http_post($data);
    }
	
    /**
     * 3.5 - Pull Recent IPs Visiting Your Site
     * This function returns a list of IP address which hit your site classified by type.
     * $zoneid = ID of the zone you would like to check. 
     * $hours = Number of hours to go back. Default is 24, max is 48.
     * $class = Restrict the result set to a given class. Currently r|s|t, for regular, crawler, threat resp.
     * $geo = Optional token. Add to add longitude and latitude information to the response. 0,0 means no data.
     */
    public function get_zone_ips($zoneid, $hours, $class, $geo = '0,0') {
        $data['a']     = 'zone_ips';
        $data['zid']   = $zoneid;
        $data['hours'] = $hours;
        $data['class'] = $class;
        $data['geo']   = $geo;
        return $this->http_post($data);
    }
	
    /**
     * 3.6 - Check The Threat Score For A Given IP
     * This function retrieves the current threat score for a given IP.
     * Note that scores are on a logarithmic scale, where a higher score indicates a higher threat.
     */
    public function threat_score($ip) {
        $data['a']  = 'ip_lkup';
        $data['ip'] = $ip;
        return $this->http_post($data);
    }
	
	
    /**
     * CLIENT API
     * Section 4
     * Modify
     */
    
    /**
     * 4.1 - Set The Security Level
     * This function sets the Basic Security Level to I'M UNDER ATTACK! / HIGH / MEDIUM / LOW / ESSENTIALLY OFF.
     * The switches are: (high|med|low|eoff).
     */
    public function set_security_lvl($mode, $domain) {
        $data['a'] = "sec_lvl";
        $data['z'] = $domain;
        $data['v'] = $mode;
        return $this->http_post($data);
    }
	
    /**
     * 4.2 - Set The Cache Level
     * This function sets the Caching Level to Aggressive or Basic.
     * The switches are: (agg|basic).
     */
    public function set_cache_lvl($mode, $domain) {
        $data['a'] = "cache_lvl";
        $data['z'] = $domain;
        $data['v'] = ($mode == 'agg') ? 'agg' : 'basic';
        return $this->http_post($data);
    }
	
    /**
     * 4.3 - Toggling Development Mode
     * This function allows you to toggle Development Mode on or off for a particular domain.
     * When Development Mode is on the cache is bypassed.
     * Development mode remains on for 3 hours or until when it is toggled back off.
     */
    public function devmode($mode, $domain) {
        $data['a'] = "devmode";
        $data['z'] = $domain;
        $data['v'] = ($mode == true) ? 1 : 0;
        return $this->http_post($data);
    }
    
    /**
     * 4.4 - Clear CloudFlare's Cache
     * This function will purge CloudFlare of any cached files.
     * It may take up to 48 hours for the cache to rebuild and optimum performance to be achieved.
     * This function should be used sparingly.
     */
    public function purge_cache($mode, $domain) {
        $data['a'] = "fpurge_ts";
        $data['z'] = $domain;
        $data['v'] = ($mode == true) ? 1 : 0;
        return $this->http_post($data);
    }
    
    /**
     * 4.6 - Update The Snapshot Of Your Site
     * This snapshot is used on CloudFlare's challenge page
     * This function tells CloudFlare to take a new image of your site.
     * Note that this call is rate limited to once per zone per day.
     * Also the new image may take up to 1 hour to appear.
     */
    public function update_image($zoneid) {
        $data['a']   = 'zone_grab';
        $data['zid'] = $zoneid;
        return $this->http_post($data);
    }
	
    /**
     * 4.7.1 - Whitelist IPs
     * You can add an IP address to your whitelist.
     */
    public function whitelist_ip($ip) {
        $data['a']   = "wl";
        $data['key'] = $ip;
        return $this->http_post($data);
    }
    
    /**
     * 4.7.2 - Blacklist IPs
     * You can add an IP address to your blacklist.
     */
    public function blacklist_ip($ip) {
        $data['a']   = "ban";
        $data['key'] = $ip;
        return $this->http_post($data);
    }
	
    /**
     * 4.7.3 - Unlist IPs
     * You can remove an IP address from the whitelist and the blacklist.
     */
    public function unlist_ip($ip) {
        $data['a']   = "nul";
        $data['key'] = $ip;
        return $this->http_post($data);
    }
    
    /**
     * 4.8 - Toggle IPv6 Support
     * This function toggles IPv6 support.
     */
    public function toggle_ipv6($zone, $mode) {
        $data['a'] = 'ipv46';
        $data['z'] = $zone;
        $data['v'] = ($mode == true) ? 1 : 0;
        return $this->http_post($data);
    }
	
	
    /**
     * CLIENT API
     * Section 5
     * DNS Record Management
     */
	
    /**
     * 5.1 - Add A New DNS Record
     * This function creates a DNS record for a zone.
     * $zone = zone
     * $type = A|CNAME
     * $id = The DNS Record ID (Available by using the rec_load_all call)
     * $content = The value of the cname or IP address (the destination)
     * $name = The name of the record you wish to create
     * $mode = 0 or 1. 0 means CloudFlare is off (grey cloud) for the new zone, while 1 means a happy orange cloud
     */
    public function add_dns_record($zone, $type, $id, $content, $name, $mode) {
        $data['a']            = 'rec_new';
        $data['type']         = ($type == 'A') ? 'A' : 'CNAME';
        $data['id']           = $id;
        $data['content']      = $content;
        $data['name']         = $name;
        $data['z']	          = $zone;
    	$data['ttl']          = '1';
        $data['service_mode'] = ($mode == true) ? 1 : 0;
        return $this->http_post($data);
    }
    
    /**
     * 5.2 - Edit A DNS Record
     * This function edits a DNS record for a zone.
     * $zone = zone
     * $type = A|CNAME
     * $id = The DNS Record ID (Available by using the rec_load_all call)
     * $content = The value of the cname or IP address (the destination)
     * $name = The name of the record you wish to create
     * $mode = 0 or 1. 0 means CloudFlare is off (grey cloud) for the new zone, while 1 means a happy orange cloud
     */
    public function update_dns_record($zone, $type, $id, $content, $name, $mode) {
        $data['a']            = 'rec_edit';
        $data['type']         = ($type == 'A') ? 'A' : 'CNAME';
        $data['id']           = $id;
        $data['content']      = $content;
        $data['name']         = $name;
        $data['z']	          = $zone;
    	$data['ttl']          = '1';
        $data['service_mode'] = ($mode == true) ? 1 : 0;
        return $this->http_post($data);
    }
    
    /**
     * 5.3 - Delete A DNS Record
     * This function deletes a DNS record for a zone.
     * $zone = zone
     * $id = The DNS Record ID (Available by using the rec_load_all call)
     * $type = A|CNAME
     */
    public function delete_dns_record($zone, $id) {
        $data['a']            = 'rec_delete';
        $data['id']           = $id;
        $data['z']	          = $zone;
        $data['service_mode'] = ($mode == true) ? 1 : 0;
        return $this->http_post($data);
    }
	
	
    /**
     * HOST API
     * Section 3
     * Specific Host Provider Operations
     */
    
    public function user_create($email, $password, $username = '', $id = '') {
        $data['act']                 = 'user_create';
        $data['cloudflare_email']    = $email;
        $data['cloudflare_pass']     = $password;
        $data['cloudflare_username'] = $username;
        $data['unique_id']           = $id;
        return $this->http_post($data, 'HOST');
    }
    
    public function zone_set($key, $zone, $resolve_to, $subdomains) {
        if (is_array($subdomains))
            $sudomains = implode(",", $subdomains);
        $data['act']        = 'zone_set';
        $data['user_key']   = $key;
        $data['zone_name']  = $zone;
        $data['resolve_to'] = $resolve_to;
        $data['subdomains'] = $subdomains;
        return $this->http_post($data, 'HOST');
    }
    
    public function user_lookup($email, $isID = false) {
        $data['act'] = 'user_lookup';
        if ($isID) {
            $data['unique_id'] = $email;
        } else {
            $data['cloudflare_email'] = $email;
        }
        return $this->http_post($data, 'HOST');
    }
    
    public function user_auth($email, $pass, $id = '') {
        $data['act']              = 'user_auth';
        $data['cloudflare_email'] = $email;
        $data['cloudflare_pass']  = $password;
        $data['unique_id']        = $id;
        return $this->http_post($data, 'HOST');
    }
    
    public function zone_lookup($zone, $user_key) {
        $data['act']       = 'zone_lookup';
        $data['user_key']  = $user_key;
        $data['zone_name'] = $zone;
        return $this->http_post($data, 'HOST');
    }
    
    public function zone_delete($zone, $user_key) {
        $data['act']       = 'zone_delete';
        $data['user_key']  = $user_key;
        $data['zone_name'] = $zone;
        return $this->http_post($data, 'HOST');
    }
    
	
    /**
     * HTTP POST a specific task with the supplied data
     */
    private function http_post($data, $type = 'USER') {
        switch ($type) {
            case 'USER':
                $data['u']   = $this->email;
                $data['tkn'] = $this->token_key;
                break;
            case 'HOST':
                $data['host_key'] = $this->host_key;
                break;
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_VERBOSE, 0);
        curl_setopt($ch, CURLOPT_FORBID_REUSE, true);
        curl_setopt($ch, CURLOPT_URL, $this->URL[$type]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_TIMEOUT, self::TIMEOUT);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $http_result = curl_exec($ch);
        $error       = curl_error($ch);
        $http_code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($http_code != 200) {
            return array(
                "error" => $error
            );
        } else {
            return json_decode($http_result);
        }
    }
}