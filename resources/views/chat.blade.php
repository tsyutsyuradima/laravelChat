@extends('layout')

@section('content')

<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>

<script>
    $(document).ready(function(){

        $('#loginform').on('submit', function (e) {
                $.ajax({
                    type: 'post',
                    url: './chat',
                    data: $('#loginform').serialize(),
                    dataType: "json",
                    success: function (json) {
                       alert("asdasd");
                    }
                });
            }
            return false;
        });

    });
</script>


<section class="section">

    <div class="connected">
        <img src="/img/unnamed.jpg" id="creatorImage" />
        <div class="infoConnected">
            <h2>Who are you?</h2>
            <br/>

            <form class="loginForm">
                <input type="text" id="yourName" placeholder="Your nick name" /><br/>
                <input type="text" id="yourEmail" placeholder="Your email address" /><br/>
                <input type="submit" id="yourEnter" value="ENTER" />
            </form>
        </div>
    </div>

    <div class="personinside">
        <img src="/img/unnamed.jpg" id="ownerImage" />
        <div class="infoInside">
            <h2>Chat with <span class="nickname-chat"></span></h2>
            <br/>

            <form class="loginForm">
                <input type="text" id="hisName" placeholder="Your nick name" /><br/>
                <input type="text" id="hisEmail" placeholder="Your email address" /><br/>
                <input type="submit" id="hisEnter" value="CHAT" />
            </form>
        </div>
    </div>

    <div class="invite-textfield">
        <h2>Oops, there are no other people in this chat!</h2>
        <h5>Invite a friend by sending them this URL</h5>
        <div class="link">
            <a title="Invite a friend" href="" id="link"></a>
        </div>
    </div>

    <div class="left">
        <img src="/img/unnamed.jpg" id="leftImage" />
        <div class="info">
            <h2><span class="nickname-left"></span> has left this chat.</h2>
            <h5>Invite somebody else by sending them this page.</h5>
        </div>
    </div>

    <div class="toomanypeople">
        <h2>Oops, you can not join this chat!</h2>
        <h5>There are already two people in it. Would you like to create a <a title="New Room" href="/create" id="room">new room</a>?</h5>
    </div>

    <div class="nomessages">
        <img src="/img/unnamed.jpg" id="noMessagesImage" />
        <div class="info">
            <h2>You are chatting with <span class="nickname-chat"></span>.</h2>
            <h5>Send them a message from the form below!</h5>
        </div>
    </div>

    <div class="chatscreen">
        <ul class="chats">
            <!-- The chat messages will go here -->
        </ul>
    </div>
</section>

<footer>
    <form id="chatform">
        <textarea id="message" placeholder="Write something.."></textarea>
        <input type="submit" id="submit" value="SEND"/>
    </form>
    <form id="loginform">
        <input id="logininput" type="email"  placeholder="Enter your email" class="form-control" name="email" value="<?php echo e(old('email')); ?>">
        <input id="logininput" type="email" placeholder="Enter your pass" class="form-control" name="email" value="<?php echo e(old('email')); ?>">
        <input type="submit" id="submit" value="Login"/>
    </form>
</footer>
@stop