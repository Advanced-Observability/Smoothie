#!/usr/bin/env bash

tmux new-session -s nload -d

tmux split-window -h
tmux select-pane -t 0
tmux split-window -v

tmux select-pane -t 2
tmux split-window -v

tmux select-pane -t 0
tmux split-window -v
tmux select-pane -t 0
tmux split-window -h
tmux select-pane -t 2
tmux split-window -h

tmux select-pane -t 4
tmux split-window -v
tmux select-pane -t 4
tmux split-window -h
tmux select-pane -t 6
tmux split-window -h

tmux select-pane -t 8
tmux split-window -v
tmux select-pane -t 8
tmux split-window -h
tmux select-pane -t 10
tmux split-window -h

tmux select-pane -t 12
tmux split-window -v
tmux select-pane -t 12
tmux split-window -h
tmux select-pane -t 14
tmux split-window -h

tmux select-pane -t 0
tmux send "nload LE1-eth3" ENTER

tmux select-pane -t 1
tmux send "nload LE1-eth4" ENTER

tmux select-pane -t 2
tmux send "nload LE2-eth3" ENTER

tmux select-pane -t 3
tmux send "nload LE2-eth4" ENTER

tmux select-pane -t 4
tmux send "nload LE3-eth3" ENTER

tmux select-pane -t 5
tmux send "nload LE3-eth4" ENTER

tmux select-pane -t 6
tmux send "nload LE4-eth3" ENTER

tmux select-pane -t 7
tmux send "nload LE4-eth4" ENTER

tmux select-pane -t 8
tmux send "nload SP5-eth1" ENTER

tmux select-pane -t 9
tmux send "nload SP5-eth2" ENTER

tmux select-pane -t 10
tmux send "nload SP5-eth3" ENTER

tmux select-pane -t 11
tmux send "nload SP5-eth4" ENTER

tmux select-pane -t 12
tmux send "nload SP6-eth1" ENTER

tmux select-pane -t 13
tmux send "nload SP6-eth2" ENTER

tmux select-pane -t 14
tmux send "nload SP6-eth3" ENTER

tmux select-pane -t 15
tmux send "nload SP6-eth4" ENTER

tmux attach-session -t nload

