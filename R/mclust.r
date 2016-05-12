library(mclust)
rm(list=ls())

table <- read.csv('result_binning.csv', header=T, sep=";", stringsAsFactors=F );

nrow <- length(unlist(strsplit(table$fph[1], ",")))
apfunc <- function(x) {
	cc <- as.numeric( unlist(strsplit(x, ",")) )
	return(cc)
}

fph <- t(matrix(apply(  table[4], 1, apfunc ), nrow=nrow ))
ppf <- t(matrix(apply(  table[5], 1, apfunc ), nrow=nrow ))
bpp <- t(matrix(apply(  table[6], 1, apfunc ), nrow=nrow ))
bps <- t(matrix(apply(  table[7], 1, apfunc ), nrow=nrow ))

df <- data.frame(fph=fph, ppf=ppf, bpp=bpp, bps=bps)
df <- as.matrix(df)

emcl = Mclust(df)
table_df <- data.frame(src=table$src_ip,dst=table$dst_ip,port=table$dst_port,fph=table$fph,ppf=table$ppf,bpp=table$bpp,bps=table$bps,cluster_id=emcl$classification)

write.table(table_df, file = "em_clustering.csv", sep = ";", col.names = NA, qmethod = "double")
write.table(summary(emcl), file = "em_summary.txt")
print("Done...")
# print(summary(emcl))
