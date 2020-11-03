sudo docker build -t repeat_your_beat:latest ./
sudo docker run --rm -p 1337:1337 --name euan -it repeat_your_beat:latest
