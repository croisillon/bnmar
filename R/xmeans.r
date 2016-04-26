# If you want to run this script, you need execute steps below
# install.packages("RWekajars", dependencies=TRUE)
# install.packages("rJava", dependencies=TRUE)
# install.packages("RWeka", dependencies=TRUE)
# After this step, restart your R


# WPM("refresh-cache")
# WPM("install-package", "XMeans")
# WPM("load-package", "XMeans")

require(RWeka)

rm(list=ls())

table <- read.csv('binned.csv', header=T, sep=";", stringsAsFactors=F );

nrow <- length(unlist(strsplit(table$fph[1], ",")))
apfunc <- function(x) {
	cc <- as.numeric( unlist(strsplit(x, ",")) )
	return(cc)
}

fph <- t(matrix(apply(  table[4], 1, apfunc ), nrow=4))
ppf <- t(matrix(apply(  table[5], 1, apfunc ), nrow=4))
bpp <- t(matrix(apply(  table[6], 1, apfunc ), nrow=4))
bps <- t(matrix(apply(  table[7], 1, apfunc ), nrow=4))

df <- data.frame(fph=fph, ppf=ppf, bpp=bpp, bps=bps)

cl <- XMeans(df, c("-L", 10, "-H", 100, "-use-kdtree", "-K", "weka.core.neighboursearch.KDTree -P"))

summary <- table(predict(cl))
table_df <- data.frame(src=table$src_ip,dst=table$dst_ip,port=table$dst_port,fph=table$fph,ppf=table$ppf,bpp=table$bpp,bps=table$bps,cluster_id=cl$class_ids)

print(summary)

write.table(table_df, file = "xmeans_clustering.csv", sep = ",", col.names = NA, qmethod = "double")
write.table(summary, file = "xmeans_summary.csv", sep = ",", col.names = NA, qmethod = "double")

print('Done')