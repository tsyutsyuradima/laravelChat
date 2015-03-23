@extends('layout')

@section('content')

<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>

<script>
    $(document).ready(function(){

        $.ajaxSetup({
            headers: {
                'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
            }
        });

        var currentUser = '<?=  Session::get('name'); ?>';
        if(currentUser != "")
        {
            $('#chatform').fadeIn(600);
        }
        else
        {
            $('#loginform').fadeIn(600);
        }

        var name = "",
            section = $(".section"),
            footer = $("footer"),
            chatScreen = $(".chatscreen"),
            left = $(".left"),
            loginForm = $(".loginForm"),
            yourName = $("#yourName"),
            yourEmail = $("#yourEmail"),
            hisName = $("#hisName"),
            hisEmail = $("#hisEmail"),
            chats = $(".chats"),
            ownerImage = $("#ownerImage"),
            leftImage = $("#leftImage"),
            noMessagesImage = $("#noMessagesImage");

        getHistory();

        function getHistory(){
            $.ajax({
                type: 'post',
                url: 'getHistory',
                dataType: "json",
                success: function (json) {
                    if (json.status === 'success')
                    {
                        chatScreen.fadeIn(600, function(){
                            scrollToBottom();
                        });
                        json.history.forEach(function(entry) {
                            createChatMessage(entry.message, entry.name, entry.created);
                        });
                    }
                    else
                    {
                        alert("OOps something worng with getting history");
                    }
                }
            });
        }

        function createChatMessage(msg,user,now){
            var li = $(
                '<li class="me">'+
                    '<div class="login">' +
                    '<b></b>' +
                    '<i class="timesent" data-time=' + now + '></i> ' +
                    '</div>' +
                    '<p></p>' +
                '</li>');
            li.find('p').text(msg);
            li.find('b').text(user);
            chats.append(li);
        }

        function scrollToBottom(){
            window.scrollTo(0,document.body.scrollHeight);
        }

        function checkHistoty(){
            $.ajax({
                type: 'post',
                url: 'checkHistory',
                dataType: "json",
                success: function (json) {
                    console.log(json);

                    if (json.status === 'update')
                    {
                        json.messages.forEach(function(entry) {
                            createChatMessage(entry.message, entry.name, entry.created);
                        });
                        scrollToBottom();
                    }
                    else
                    {
                    }
                }
            });
        }

        $('#loginform').on('submit', function (e) {
            $("#loginform #submit").fadeOut(300);
            $.ajax({
                type: 'post',
                url: 'login',
                data: $('#loginform').serialize(),
                dataType: "json",
                success: function (json) {
                    console.log(json);

                    if (json.status === 'success')
                    {
                        var user_name = json.user.name;
                        var user_id = json.user.id;
                        $('#loginform').fadeOut(600,function(){
                            $('#chatform').fadeIn(600);
                        });
                    }
                    else if (json.status === 'error')
                    {
                        $("#loginform #submit").fadeIn(300);
                    }
                }
            });
            return false;
        });

        $('#chatform').on('submit', function (e) {
            $.ajax({
                type: 'post',
                url: 'sendMessage',
                data: $('#chatform').serialize(),
                dataType: "json",
                success: function (json) {
                    $('#message').val('');
                }
            });
            return false;
        });

        setInterval(function() {
            checkHistoty();
        }, 2000);
    });
</script>

<section class="section">
    <div class="chatscreen">
        <ul class="chats">
        </ul>
    </div>
</section>

<footer>
    <form id="chatform">
        <textarea id="message" name="message" placeholder="Write something.."></textarea>
        <input type="submit" id="submit" value="SEND"/>
    </form>
    <form id="loginform">
        <input id="logininput" type="text" placeholder="Enter your login" class="form-control" name="login" value="<?php echo e(old('login')); ?>">
        <input id="logininput" type="password" placeholder="Enter your password" class="form-control" name="password" value="<?php echo e(old('password')); ?>">
        <input type="submit" id="submit" value="Login"/>
    </form>
</footer>

@stop