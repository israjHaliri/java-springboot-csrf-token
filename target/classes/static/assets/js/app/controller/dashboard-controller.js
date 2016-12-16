/**
 * Created by Israj PC on 11/1/2016.
 */
app.controller('dashboardController', function($scope, $http, $location, $routeParams, $cookies) {

    console.log($cookies.get('XSRF-TOKEN'));

    $scope.initData = function(){
        $http({
            url: "http://localhost:8181/api/dashboard",
            dataType: 'json',
            method: 'GET',
            headers: {
                "Content-Type": "application/json",
                'X-XSRF-TOKEN': $cookies.get('XSRF-TOKEN')
            }

        }).success(function (response) {
            console.log(response);
            $scope.username = response.data
        }, function myError(response) {
            console.log("load error response =", response);
        });

    };


    $scope.initData();
});