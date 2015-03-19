<html>
<head>
    <link type="text/css" rel="stylesheet" href="/css/main.css" />
    <link href="http://fonts.googleapis.com/css?family=Open+Sans Condensed:300italic,300,700" rel="stylesheet" type="text/css">
    <meta name="csrf-token" content="{{ csrf_token() }}" />
</head>

<body>
@yield('content')
</body>
</html>