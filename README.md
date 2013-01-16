#Shodan API

PHP wrapper for the Shodan API [http://www.shodanhq.com/](http://www.shodanhq.com/)

#Example

	$shodan = new \JTet\Shodan\WebAPI("your api key");
	$results = $shodan->search("apache");
