var app = angular.module('myApp', ['ngRoute','ngCookies']);

app.config(function ($routeProvider,$httpProvider) {

	$routeProvider
		.when('/', {templateUrl: 'pages/login.html', controller: 'loginController'})
		.when('/dashboard', {templateUrl: 'pages/dashboard.html', controller: 'dashboardController'})
		.otherwise({redirectTo: '/'});

	$httpProvider.interceptors.push(['$q', '$location', function ($q, $location) {

		return {
			'responseError': function(response) {

				if(response.status === 401 || response.status === 403) {
					// window.location = "/login"
					$location.path("/");
				}
				return $q.reject(response);
			}
		};
	}]);

});


app.run(function($rootScope,$http) {
	var base_url = window.location.host;
	console.log(base_url);

	$rootScope.logout = function(){

		$http({
			url: base_url+'/logout',
			dataType: 'json',
			method: 'POST'
		}).success(function(response){
			location.reload();
		}, function myError(response) {
			console.log("error logout =",response);
		});
	};
});