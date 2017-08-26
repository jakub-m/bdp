set terminal png size 800,600
set output output_fname

plot input_fname using 1:2:0 with points pointtype 7 pointsize 1 palette
