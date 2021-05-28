#!/usr/bin/env python3

import csv
from pprint import pprint
import sys, bs4
import copy

soup = bs4.BeautifulSoup(open(sys.argv[1]), features='lxml')

cols = [t.text for t in soup.thead.tr.find_all('th')]
cols.insert(6, 'Security state (S)')
cols[5] = 'Security state (NS)'
assert len(cols) == 9

n_cols = 0
n_rows = 0
for row in soup.tbody.find_all('tr'):
    col_tags = row.find_all("td")
    if len(col_tags) > 0:
        n_rows += 1
        if len(col_tags) > n_cols:
            n_cols = len(col_tags)

assert n_cols == len(cols)

coldata = [["N/A" for i in range(n_cols)] for j in range(n_rows)]
rowskip = [[0 for i in range(n_cols)] for j in range(n_rows)]
colskip = [[0 for i in range(n_cols)] for j in range(n_rows)]

# Adapted from https://johnricco.github.io/2017/04/04/python-html/
skip_index = [0 for i in range(0, n_cols)]
row_counter = 0
for row in soup.tbody.find_all('tr'):
    columns = row.find_all("td")
    col_dim = []
    row_dim = []
    col_dim_counter = -1
    row_dim_counter = -1
    col_counter = -1
    this_skip_index = copy.deepcopy(skip_index)
    
    for col in columns:
        colspan = col.get("colspan")
        if colspan is None:
            col_dim.append(1)
        else:
            col_dim.append(int(colspan))
        col_dim_counter += 1

        rowspan = col.get("rowspan")
        if rowspan is None:
            row_dim.append(1)
        else:
            row_dim.append(int(rowspan))
        row_dim_counter += 1

        if col_counter == -1:
            col_counter = 0
        else:
            col_counter = col_counter + col_dim[col_dim_counter - 1]
        
        while skip_index[col_counter] > 0:
            col_counter += 1

        cell_data = col.get_text()
        coldata[row_counter][col_counter] = cell_data
        if rowspan is not None:
            rowskip[row_counter][col_counter] = int(rowspan)
        if colspan is not None:
            colskip[row_counter][col_counter] = int(colspan)
        
        if row_dim[row_dim_counter] > 1:
            this_skip_index[col_counter] = row_dim[row_dim_counter]
    row_counter += 1
    skip_index = [i - 1 if i > 0 else i for i in this_skip_index]

# Fill in duplicate values from row/col skip record
for i,row in enumerate(rowskip):
    for j,col in enumerate(row):
        if col != 0:
            for k in range(i,i+col):
                coldata[k][j] = coldata[i][j]
for i,row in enumerate(colskip):
    for j,col in enumerate(row):
        if col != 0:
            for k in range(j,j+col):
                coldata[i][k] = coldata[i][j]

# Finally, empty values will inherit the column above
for i,row in enumerate(coldata):
    for j,col in enumerate(row):
        if col == "": coldata[i][j] = coldata[i-1][j]

of = open(sys.argv[1] + '.csv','w')
wr = csv.DictWriter(of, fieldnames=cols)
wr.writeheader()
for row in coldata:
    wr.writerow(dict(zip(cols,row)))
of.close()
