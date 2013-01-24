<?php
namespace JTet\Shodan;

/**
 * PHP Wrapper around the SHODAN webservices API
 *
 * Based on the wrapper written by jordan-wright (jmwright798 at gmail.com)
 * Original at https://github.com/jordan-wright/shodan-php/blob/master/shodan-php.php
 *
 * SHODAN Database designed and maintained by achillean (John Matherly)
 * SHODAN website: http://www.shodanhq.com
 * Follow achillean on twitter: http://twitter.com/#!/achillean
 */
class WebAPI
{
    const SERVICE_ENDPOINT = "http://www.shodanhq.com/api/";

    protected $key;

    /**
     *  Constructor - Instantiates WebAPI object
     *  Example: $shodan = new WebAPI("your API key");
     *
     * @param string $apiKey
     */
    public function __construct($apiKey)
    {
        $this->key = $apiKey;
    }


    /**
     * General CURL Request function
     * Arguments:	function - function to be performed (Example: "search")
     * params - Associative array of arguments to that function
     *
     * Returns: Associative array of JSON decoded output from the SHODAN webservice
     *
     * @param string $function
     * @param array  $params
     *
     * @return mixed
     */
    protected function _request($function, $params)
    {
        $params = array("key" => $this->key) + $params;
        $url = WebAPI::SERVICE_ENDPOINT . "$function?" . http_build_query($params);
        $req = curl_init($url);
        curl_setopt($req, CURLOPT_RETURNTRANSFER, true);
        $ret = curl_exec($req);
        curl_close($req);

        return json_decode($ret, true);

    }

    /**
     * Search Function
     * Arguments:	query - Query to be searched for
     *
     * Returns: Result (associative array) from SHODAN webservices
     *
     * @param string $query
     *
     * @return mixed
     */
    public function search($query)
    {
        return $this->_request("search", array("q" => $query));
    }

    /**
     * Exploit DB Download Function
     * Arguments:	id - Exploit DB ID of wanted exploit
     * Returns: Result (associative array) from SHODAN webservices
     *
     * @param $id
     *
     * @return mixed
     */
    public function exploitdb_download($id)
    {
        return $this->_request("exploitdb/download", array("id" => $id));
    }

    /**
     * Exploit DB Search Function
     * Arguments:	query - Query to be searched for
     * args - Associative array of other arguments to better define query
     *
     * Returns: Result (associative array) from SHODAN webservices
     *
     * @param $query
     * @param $args
     *
     * @return mixed
     */
    public function exploitdb_search($query, $args)
    {
        $args = array("q" => $query) + $args;

        return $this->_request("exploitdb/search", $args);
    }

    /**
     * Host Search Function
     * Arguments:	ip - IP Address of specified host(s)
     *
     * Returns: Result (associative array) from SHODAN webservices
     *
     * @param $ip
     *
     * @return mixed
     */
    public function host($ip)
    {
        return $this->_request("host", array("ip" => $ip));
    }

    /**
     * Fingerprint Function
     * Arguments:	banner - HTTP Banner
     *
     * Returns: Result (associative array) from SHODAN webservices
     *
     * @param $banner
     *
     * @return mixed
     */
    public function fingerprint($banner)
    {
        return $this->_request("fingerprint", array("banner" => $banner));
    }

    /**
     * Locations Function
     * Arguments:	query - Query to be searched for
     *
     * Returns: Result (associative array) from SHODAN webservices
     *
     * @param $query
     *
     * @return mixed
     */
    public function locations($query)
    {
        return $this->_request("locations", array("q" => $query));
    }

    /**
     * MSF Download Function
     * Arguments: id - fullname of Metasploit Module
     *
     * Returns: Result (associative array) from SHODAN webservices
     *
     * @param $id
     *
     * @return mixed
     */
    public function msf_download($id)
    {
        return $this->_request("msf/download", array("id" => $id));
    }

    /**
     * MSF Search Function
     * Arguments: query - Metasploit module to be searched for
     *
     * Returns: Result (associative array) from SHODAN webservices
     *
     * @param $query
     * @param $args
     *
     * @return mixed
     */
    public function msf_search($query, $args)
    {
        $args = array("q" => $query) + $args;

        return $this->_request("msf/search", $args);
    }
}