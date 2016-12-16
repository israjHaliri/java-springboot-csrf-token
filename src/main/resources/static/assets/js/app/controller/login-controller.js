app.controller('loginController', function($scope,$http,$location,$cookies) {

	console.log($cookies.get('XSRF-TOKEN'));


	$scope.login = function(){

		$http({
			url: "http://localhost:8181/login",
			method: 'POST',
			data: $.param({
				username: $scope.username,
				password: $scope.password
			}),
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'X-XSRF-TOKEN': $cookies.get('XSRF-TOKEN')
			}

		}).success(function (response) {
			console.log("login success response =", response);
			if(response == "OK" ){
				$location.path("/dashboard");
			}
		}, function myError(response) {
			console.log("login error response =", response);
		});

	};
});