#!/bin/bash
# JSex Unit Tests
# by Vikman
# June 4, 2017

INPUT='{"_id":"5933334cfa67938e672671be","index":0,"guid":"1bbb378e-9a35-47c0-ba09-561baecb0ab5","isActive":false,"balance":"$2,448.16","picture":"http://placehold.it/32x32","age":27,"eyeColor":"brown","name":"Murray Hurst","gender":"male","company":"NETAGY","email":"murrayhurst@netagy.com","phone":"+1 (850) 561-3207","address":"573 Herkimer Place, Matheny, Nevada, 234","about":"Sunt magna dolore nostrud reprehenderit nostrud laboris est eu irure id consectetur in ea. Commodo eiusmod Lorem laborum esse ut est. Non adipisicing enim culpa deserunt dolor officia ullamco consectetur nisi velit consectetur fugiat. Enim duis esse velit dolore voluptate sint occaecat pariatur et ad velit ut dolore irure. Aute sit ad nisi mollit. Eu proident nostrud mollit ea labore amet. Nisi id magna nulla ex eu deserunt occaecat.\r\n","registered":"2016-06-04T06:54:47 -02:00","latitude":69.569818,"longitude":114.829979,"tags":["et","sit","fugiat","deserunt","aliqua","Lorem","enim"],"friends":[{"id":0,"name":"Deloris Doyle"},{"id":1,"name":"Jeannie Mcfarland"},{"id":2,"name":"Pope Skinner"}],"greeting":"Hello, Murray Hurst! You have 1 unread messages.","favoriteFruit":"apple"}'

ERROR=0

main() {
    test "favoriteFruit" "\"apple\""
    test "latitude + longitude" "184.399797"
    test "any tag in tags: (tag == \"enim\")" "true"
    test "all tag in tags: (!(tag =~ \"^a\"))" "false"
    test "tags[5] + \" ipsum\"" "\"Lorem ipsum\""
}

test() {
    echo -n "Testing '$1' -> $2"
    output=$(./jsex "$INPUT" "$1")

    if [ $? == 0 ] && [ "$(echo "$output" | grep "Result: .*" | tail -c +9)" == "$2" ]
    then
        echo -e "\r\t\t\t\t\t\t\t\t\t[OK]"
    else
        ERROR=1
        echo -e "\r\t\t\t\t\t\t\t\t\t[FAIL]"
        echo "$output"
        echo "$(echo "$output" | grep "Result: .*" | tail -c +9)"
    fi
}

if [ "${BASH_SOURCE[0]}" == "${0}" ]
then
    main
    exit $ERROR
fi
