source('R/functions.r')

library(fpc)

sub_dbscan <- function ( input_dir, output_dir, file_name ) {
	msg <- paste( "Running DBSCAN algorithm for file: ", file_name, sep='' )
	print(msg)

	dir.create( output_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )
	input_file_name <- file.path( input_dir, file_name )
	output_file_name <- file.path( output_dir, file_name )

	table <- sub_read_csv( input_file_name )

	dbmx <- as.matrix( sub_create_structure( table, c('fph') ) )

	dbclust <- dbscan(dbmx, 1.5, MinPts=4, seed=F)

	dbtable <- data.frame(src=table$src_ip,dst=table$dst_ip,port=table$dst_port,fph=table$fph,ppf=table$ppf,bpp=table$bpp,bps=table$bps,cluster_id=dbclust$cluster)

	write.table(dbtable, file = output_file_name, sep = ";", col.names = NA, qmethod = "double")

	rm(table, dbmx, dbclust, dbtable)
}